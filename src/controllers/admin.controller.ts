import { Request, Response } from 'express';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs/promises';
import os from 'os';
import { supabaseAdmin } from '../lib/supabase.ts';
import { prisma } from '../lib/prisma.ts';


export const createUser = async (req: Request, res: Response) => {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
        return res.status(400).json({ message: 'Email, password, and role are required' });
    }

    if (!['admin', 'user'].includes(role)) {
        return res.status(400).json({ message: 'Role must be admin or user' });
    }

    try {
        const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
            email,
            password,
            email_confirm: true,
        });

        if (authError) {
            return res.status(400).json({ message: authError.message });
        }

        if (!authData.user) {
            return res.status(500).json({ message: 'Failed to create user' });
        }

        const profile = await prisma.profile.create({
            data: {
                user_id: authData.user.id,
                email: authData.user.email!,
                role,
            },
        });


        return res.status(201).json({
            id: authData.user.id,
            email: profile.email,
            role: profile.role,
        });
    } catch (err: any) {
        console.error('Create user error:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

export const deleteUser = async (req: Request, res: Response) => {
    const { id } = req.params;

    try {
        const { error: authError } = await supabaseAdmin.auth.admin.deleteUser(id);

        if (authError) {
            return res.status(400).json({ message: authError.message });
        }

        await prisma.profile.deleteMany({
            where: { user_id: id },
        });

        return res.json({ message: 'User deleted' });
    } catch (err: any) {
        console.error('Delete user error:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};


export const backup = (req: Request, res: Response) => {
    const dbUrl = process.env.DATABASE_URL;
    const pgDumpPath = process.env.PG_DUMP_PATH || 'pg_dump';

    if (!dbUrl) {
        return res.status(500).json({ message: 'DATABASE_URL not configured' });
    }

    const filename = `backup-${new Date().toISOString().replace(/[:.]/g, '-')}.dump`;

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    const pgDump = spawn(pgDumpPath, [
        '--format=custom',
        '--no-acl',
        '--no-owner',
        dbUrl,
    ]);

    pgDump.stdout.pipe(res);

    pgDump.stderr.on('data', (data) => {
        console.error(`pg_dump stderr: ${data}`);
    });

    pgDump.on('error', (err) => {
        console.error('pg_dump error:', err);
        if (!res.headersSent) {
            res.status(500).json({ message: 'Backup failed to start' });
        } else {
            res.destroy();
        }
    });

    pgDump.on('close', (code) => {
        if (code !== 0) {
            console.error(`pg_dump exited with code ${code}`);
        }
        if (!res.writableEnded) {
            res.end();
        }
    });
};


export const restore = async (req: Request, res: Response) => {
    const dbUrl = process.env.DATABASE_URL;
    const pgRestorePath = process.env.PG_RESTORE_PATH || 'pg_restore';
    const pgDumpPath = process.env.PG_DUMP_PATH || 'pg_dump';
    const safetyDir = process.env.SAFETY_SNAPSHOT_DIR || './safety_snapshots';

    if (!dbUrl) {
        return res.status(500).json({ message: 'DATABASE_URL not configured' });
    }

    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }

    const tempPath = req.file.path;

    try {
        // 1. Validate magic bytes for .dump files
        if (req.file.originalname.toLowerCase().endsWith('.dump')) {
            const fd = await fs.open(tempPath, 'r');
            const buffer = Buffer.alloc(4);
            await fd.read(buffer, 0, 4, 0);
            await fd.close();

            // PGDM = 0x50 0x47 0x44 0x4D
            if (buffer.toString('hex') !== '5047444d') {
                await fs.unlink(tempPath).catch(() => { });
                return res.status(400).json({ message: 'Invalid PostgreSQL custom dump format' });
            }
        }

        // 2. Ensure safety directory exists
        await fs.mkdir(safetyDir, { recursive: true });

        // 3. Take safety snapshot
        const timestamp = Date.now();
        const safetyPath = path.join(safetyDir, `safety_snapshot_${timestamp}.dump`);

        await new Promise<void>((resolve, reject) => {
            const safetyDump = spawn(pgDumpPath, [
                '--format=custom',
                '--no-acl',
                '--no-owner',
                dbUrl,
            ]);

            const writeStream = require('fs').createWriteStream(safetyPath);
            safetyDump.stdout.pipe(writeStream);

            safetyDump.stderr.on('data', (data: Buffer) => {
                console.error(`Safety snapshot stderr: ${data}`);
            });

            safetyDump.on('error', reject);
            safetyDump.on('close', (code) => {
                if (code === 0) resolve();
                else reject(new Error(`Safety snapshot failed with code ${code}`));
            });
        });

        // 4. Restore from uploaded file
        const restoreResult = await runPgRestore(pgRestorePath, dbUrl, tempPath);

        // Clean up uploaded temp file
        await fs.unlink(tempPath).catch(() => { });

        if (restoreResult.success) {
            return res.json({
                message: 'Restore completed successfully',
                snapshotPath: safetyPath,
            });
        }

        // 5. Restore failed — attempt rollback
        console.error('Restore failed, attempting rollback from safety snapshot...');
        const rollbackResult = await runPgRestore(pgRestorePath, dbUrl, safetyPath);

        if (rollbackResult.success) {
            return res.status(500).json({
                message: 'Restore failed. Database rolled back to safety snapshot.',
                error: restoreResult.error,
                snapshotPath: safetyPath,
            });
        }

        return res.status(500).json({
            message: 'Restore failed and rollback also failed.',
            error: restoreResult.error,
            rollbackError: rollbackResult.error,
            snapshotPath: safetyPath,
        });
    } catch (err: any) {
        await fs.unlink(tempPath).catch(() => { });
        console.error('Restore error:', err);
        return res.status(500).json({ message: 'Restore failed', error: err.message });
    }
};

// Helper: run pg_restore and capture result
function runPgRestore(
    pgRestorePath: string,
    dbUrl: string,
    filePath: string
): Promise<{ success: boolean; error?: string }> {
    return new Promise((resolve) => {
        const pgRestore = spawn(pgRestorePath, [
            '--clean',
            '--if-exists',
            '--no-owner',
            '--no-acl',
            `--dbname=${dbUrl}`,
            filePath,
        ]);

        let errorOutput = '';

        pgRestore.stderr.on('data', (data: Buffer) => {
            errorOutput += data.toString();
        });

        pgRestore.on('error', (err) => {
            resolve({ success: false, error: err.message });
        });

        pgRestore.on('close', (code) => {
            // pg_restore: 0 = success, 1 = warnings but completed, 2+ = fatal
            if (code === 0 || code === 1) {
                resolve({ success: true });
            } else {
                resolve({ success: false, error: errorOutput || `Exit code ${code}` });
            }
        });
    });
}