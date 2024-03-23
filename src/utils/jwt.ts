import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import {SECRET_KEY} from '../config/secrets';

const ACCESS_TOKEN_EXPIRES_IN = 15 * 60 * 60;
const REFRESH_TOKEN_EXPIRES_IN = 24 * 60 * 60 * 60;

export type PayloadType = {
  id: string;
  type: 'access' | 'refresh';
};

export type ReturnType = PayloadType & {
  exp: number;
  iat: number;
};

export type TokenType = {
  token: string;
  expiresIn: number;
};

export const issueToken = (payload: PayloadType): TokenType => {
  const expiresIn =
    payload.type === 'access'
      ? ACCESS_TOKEN_EXPIRES_IN
      : REFRESH_TOKEN_EXPIRES_IN;
  const token = jwt.sign(payload, SECRET_KEY, {
    expiresIn,
  });
  return {token, expiresIn};
};

export const verifyToken = (token: string): ReturnType | null => {
  try {
    const payload = jwt.verify(token, SECRET_KEY);

    if (!payload || typeof payload === 'string') {
      throw Error('Invalid token');
    }

    return payload as ReturnType;
  } catch (error) {
    return null;
  }
};

export const hashToken = (token: string): string => {
  return crypto.createHash('sha256').update(token).digest('hex');
};
