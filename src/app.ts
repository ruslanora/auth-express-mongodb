import cors from 'cors';
import errorHandler from 'errorhandler';
import express from 'express';
import helmet from 'helmet';
import {ENVIRONMENT} from './config/secrets';

const app = express();

app.set('port', process.env.PORT || 3000);
app.set('env', ENVIRONMENT);

app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({extended: true}));

if (process.env.NODE_ENV === 'development') {
  app.use(errorHandler());
}

export default app;
