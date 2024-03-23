import bluebird from 'bluebird';
import cors from 'cors';
import errorHandler from 'errorhandler';
import express from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import logger from './utils/logger';
import routes from './api';
import {ENVIRONMENT, DATABASE_URI} from './config/secrets';

const app = express();

mongoose.Promise = bluebird;

if (ENVIRONMENT !== 'test') {
  mongoose
    .connect(DATABASE_URI, {})
    .then(() => {
      logger.info('The database connection is established.');
    })
    .catch(error => {
      logger.error("Couldn't establish a database connection.");
      throw error;
    });
}

app.set('port', process.env.PORT || 3000);
app.set('env', ENVIRONMENT);

app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({extended: true}));

app.use('/api', routes);

if (process.env.NODE_ENV === 'development') {
  app.use(errorHandler());
}

export default app;
