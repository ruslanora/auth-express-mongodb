import {Router} from 'express';
import authRoutes from './auth.api';

const router = Router();

router.use('/auth', authRoutes);

export default router;
