import bcrypt from 'bcrypt';
import {Response, Request, Router} from 'express';
import {BlacklistedToken} from '../../models/BlacklistedToken';
import {User} from '../../models/User';
import * as jwt from '../../utils/jwt';
import * as password from '../../utils/password';

const router = Router();

/**
 * @swagger
 * /api/v1/auth/register:
 *  post:
 *    summary: Register a new user
 *    tags: [authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required:
 *              - email
 *              - password1
 *              - password2
 *            properties:
 *              email:
 *                type: string
 *                format: email
 *              password1:
 *                type: string
 *                format: password
 *                description: Primary email
 *              password2:
 *                type: string
 *                format: password
 *                description: Must match password1
 *    responses:
 *      201:
 *        description: Successfully registered
 *        content:
 *          application/json:
 *            schema:
 *               type: object
 *               properties:
 *                 access_token:
 *                   type: string
 *                 access_token_expires_in:
 *                   type: integer
 *                 refresh_token:
 *                   type: string
 *                 refresh_token_expires_in:
 *                   type: integer
 *      400:
 *         description: Invalid input or user already exists
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 */
router.post('/register', async (req: Request, res: Response) => {
  const {email, password1, password2} = req.body;

  if (!email || !password1 || !password2) {
    return res
      .status(400)
      .json({message: 'Email or passwords are not provided'});
  }

  if (password1 !== password2) {
    return res.status(400).json({messages: "Passwords don't match"});
  }

  const isWeak = password.isWeak(password1, [email]);

  if (isWeak) {
    return res.status(400).json({message: isWeak});
  }

  const existingUser = await User.findOne({email});

  if (existingUser) {
    return res.status(400).json({
      message: 'Email is already in use',
    });
  }

  const user = new User({email, password: password1});
  await user.save();

  const userId = user._id.toString();
  const access = jwt.issueToken({id: userId, type: 'access'});
  const refresh = jwt.issueToken({id: userId, type: 'refresh'});

  return res.status(201).json({
    access_token: access.token,
    access_token_expires_in: access.expiresIn,
    refresh_token: refresh.token,
    refresh_token_expires_in: refresh.expiresIn,
  });
});

/**
 * @swagger
 * /api/v1/auth/login:
 *  post:
 *    summary: Log in
 *    tags: [authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required:
 *              - email
 *              - password
 *            properties:
 *              email:
 *                type: string
 *                format: email
 *              password:
 *                type: string
 *                format: password
 *                description: Primary email
 *    responses:
 *      201:
 *        description: Successfully logged in
 *        content:
 *          application/json:
 *            schema:
 *               type: object
 *               properties:
 *                 access_token:
 *                   type: string
 *                 access_token_expires_in:
 *                   type: integer
 *                 refresh_token:
 *                   type: string
 *                 refresh_token_expires_in:
 *                   type: integer
 *      400:
 *         description: Invalid input or user doesn't exist
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 */
router.post('/login', async (req: Request, res: Response) => {
  const {email, password} = req.body;

  if (!email || !password) {
    return res.status(400).json({message: 'Credentials are not provided'});
  }

  const user = await User.findOne({email});

  if (!user) {
    return res.status(400).json({message: 'Credentials are invalid'});
  }

  const matched = await bcrypt.compare(password, user.password);

  if (!matched) {
    return res.status(400).json({message: 'Credentials are invalid'});
  }

  const userId = user._id.toString();
  const access = jwt.issueToken({id: userId, type: 'access'});
  const refresh = jwt.issueToken({id: userId, type: 'refresh'});

  return res.status(201).json({
    access_token: access.token,
    access_token_expires_in: access.expiresIn,
    refresh_token: refresh.token,
    refresh_token_expires_in: refresh.expiresIn,
  });
});

/**
 * @swagger
 * /api/v1/auth/refresh:
 *  post:
 *    summary: Issues a new token pair
 *    tags: [authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required:
 *              - refresh_token
 *            properties:
 *              refresh_token:
 *                type: string
 *                format: string
 *    responses:
 *      201:
 *        description: Successfully refreshed
 *        content:
 *          application/json:
 *            schema:
 *               type: object
 *               properties:
 *                 access_token:
 *                   type: string
 *                 access_token_expires_in:
 *                   type: integer
 *                 refresh_token:
 *                   type: string
 *                 refresh_token_expires_in:
 *                   type: integer
 *      400:
 *         description: Invalid or expired refresh token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 */
router.post('/refresh', async (req: Request, res: Response) => {
  const {refresh_token} = req.body;

  if (!refresh_token) {
    return res.status(400).json({message: 'Missing refresh token'});
  }

  const payload = jwt.verifyToken(refresh_token);

  if (!payload || (payload && payload.type && payload.type === 'access')) {
    return res.status(400).json({message: 'Invalid refresh token'});
  }

  const isBlacklisted = await BlacklistedToken.findOne({
    token: jwt.hashToken(refresh_token),
  });

  if (isBlacklisted) {
    return res.status(400).json({message: 'Token has been revoked'});
  }

  await BlacklistedToken.create({
    token: jwt.hashToken(refresh_token),
    expiresAt: new Date(payload.exp * 1000),
  });

  const user = await User.findById(payload.id);

  if (!user) {
    return res.status(400).json({message: 'Invalid refresh token'});
  }

  const userId = user._id.toString();
  const access = jwt.issueToken({id: userId, type: 'access'});
  const refresh = jwt.issueToken({id: userId, type: 'refresh'});

  return res.status(201).json({
    access_token: access.token,
    access_token_expires_in: access.expiresIn,
    refresh_token: refresh.token,
    refresh_token_expires_in: refresh.expiresIn,
  });
});

/**
 * @swagger
 * /api/v1/auth/verify:
 *  post:
 *    summary: Validates an access token
 *    tags: [authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required:
 *              - access_token
 *            properties:
 *              access_token:
 *                type: string
 *                format: string
 *    responses:
 *      200:
 *        description: The token is valid
 *        content:
 *          application/json:
 *            schema:
 *               type: object
 *               properties:
 *                 user_id:
 *                   type: string
 *      400:
 *         description: Invalid or expired access token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 */
router.post('/verify', (req: Request, res: Response) => {
  const {access_token} = req.body;

  if (!access_token) {
    return res.status(400).json({message: 'Missing access token'});
  }

  const payload = jwt.verifyToken(access_token);

  if (!payload || (payload && payload.type && payload.type === 'refresh')) {
    return res.status(400).json({message: 'Invalid access token'});
  }

  return res.status(200).json({user_id: payload.id});
});

/**
 * @swagger
 * /api/v1/auth/revoke:
 *  post:
 *    summary: Blacklists a refresh token
 *    tags: [authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required:
 *              - refresh_token
 *            properties:
 *              refresh_token:
 *                type: string
 *                format: string
 *    responses:
 *      200:
 *        description: The token has been blacklisted
 *        content:
 *          application/json:
 *            schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *      400:
 *         description: Invalid or expired refresh token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 */
router.post('/revoke', async (req: Request, res: Response) => {
  const {refresh_token} = req.body;

  if (!refresh_token) {
    return res.status(400).json({message: 'Missing refresh token'});
  }

  const payload = jwt.verifyToken(refresh_token);

  if (!payload || (payload && payload.type && payload.type === 'access')) {
    return res.status(400).json({message: 'Invalid refresh token'});
  }

  try {
    await BlacklistedToken.create({
      token: jwt.hashToken(refresh_token),
      expiresAt: new Date(payload.exp * 1000),
    });
  } catch (error) {
    // Do nothing...
  }

  res.status(200).json({message: 'Token has been revoked'});
});

export default router;
