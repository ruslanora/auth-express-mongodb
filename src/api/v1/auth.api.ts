import bcrypt from 'bcrypt';
import {Response, Request, Router} from 'express';
import {BlacklistedToken} from '../../models/BlacklistedToken';
import {User} from '../../models/User';
import * as jwt from '../../utils/jwt';
import * as password from '../../utils/password';

const router = Router();

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
