import dotenv from 'dotenv';
import fs from 'fs';
import logger from '../utils/logger';

export const ENVIRONMENT = process.env.NODE_ENV || 'development';

switch (ENVIRONMENT) {
  case 'development':
    if (fs.existsSync('.env.development')) {
      logger.debug('Using .env.development file');
      dotenv.config({path: '.env.development'});
    }
    break;
  case 'staging':
    if (fs.existsSync('.env.staging')) {
      logger.debug('Using .env.staging file');
      dotenv.config({path: '.env.staging'});
    }
    break;
  case 'production':
    if (fs.existsSync('.env.production')) {
      logger.debug('Using .env.production file');
      dotenv.config({path: '.env.production'});
    }
    break;
  default:
    if (fs.existsSync('.env.example')) {
      logger.debug('Using .env.example file');
      dotenv.config({path: '.env.example'});
    }
    break;
}

export const DATABASE_URI = process.env['DATABASE_URI'] as string;

if (!DATABASE_URI) {
  logger.error("Couldn't find DATABASE_URI environment variable.");
  throw Error;
}

export const SECRET_KEY = process.env['SECRET_KEY'] as string;

if (!SECRET_KEY) {
  logger.error("Couldn't find SECRET_KEY environment variable.");
  throw Error;
}
