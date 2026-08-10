import { Router } from 'express';
import path from 'path';
import os from 'os';
import { createUser, deleteUser } from '../controllers/admin.controller.ts';
import { authenticate } from '../middleware/authenticate.ts';
import { requireAdmin } from '../middleware/requireAdmin.ts';

const router = Router();

// User management
router.post('/users', authenticate, requireAdmin, createUser);
router.delete('/users/:id', authenticate, requireAdmin, deleteUser);

export default router;