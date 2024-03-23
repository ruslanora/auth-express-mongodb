import {MongoMemoryServer} from 'mongodb-memory-server';
import mongoose from 'mongoose';
import request from 'supertest';
import app from '../../src/app';

const VALID_EMAIL = 'test@example.com';
const VALID_PASSWORD = '76pZz61e7x!';

let mongo: MongoMemoryServer;

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri());
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongo.stop();
});

const login = async () => {
  const response = await request(app).post('/api/v1/auth/login').send({
    email: VALID_EMAIL,
    password: VALID_PASSWORD,
  });

  return response;
};

describe('/api/v1/auth/register', () => {
  const uri = '/api/v1/auth/register';

  it('should successfully register a user', async () => {
    const response = await request(app).post(uri).send({
      email: VALID_EMAIL,
      password1: VALID_PASSWORD,
      password2: VALID_PASSWORD,
    });

    expect(response.status).toBe(201);
    expect(response.body).toHaveProperty('refresh_token');
    expect(response.body).toHaveProperty('refresh_token_expires_in');
    expect(response.body).toHaveProperty('access_token');
    expect(response.body).toHaveProperty('access_token_expires_in');
  });

  it('should fail as email is already in use', async () => {
    const response = await request(app).post(uri).send({
      email: VALID_EMAIL,
      password1: VALID_PASSWORD,
      password2: VALID_PASSWORD,
    });

    expect(response.status).toBe(400);
  });

  it('should fail password validation', async () => {
    let response = await request(app).post(uri).send({
      email: 'test@test.com',
      password1: 'test@test',
      password2: 'test@test',
    });

    expect(response.status).toBe(400);

    response = await request(app).post(uri).send({
      email: 'test@test.com',
      password1: 'test@test1',
      password2: 'test@test',
    });

    expect(response.status).toBe(400);

    response = await request(app).post(uri).send({
      email: 'test@test.com',
      password1: 'Test1234!',
      password2: 'Test1234!',
    });

    expect(response.status).toBe(400);
  });

  describe('/api/v1/auth/login', () => {
    const uri = '/api/v1/auth/login';

    it('should successfully log in', async () => {
      const response = await login();

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('refresh_token');
      expect(response.body).toHaveProperty('refresh_token_expires_in');
      expect(response.body).toHaveProperty('access_token');
      expect(response.body).toHaveProperty('access_token_expires_in');
    });

    it('should fail due to password mismatch', async () => {
      const response = await request(app)
        .post(uri)
        .send({
          email: VALID_EMAIL,
          password: VALID_PASSWORD + '1234',
        });

      expect(response.status).toBe(400);
    });
  });

  describe('/api/v1/auth/refresh', () => {
    const uri = '/api/v1/auth/refresh';
    let token: string = '';

    it('should successfully refrech tokens', async () => {
      let response = await login();

      expect(response.body).toHaveProperty('refresh_token');
      token = response.body.refresh_token;

      response = await request(app).post(uri).send({
        refresh_token: token,
      });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('refresh_token');
      expect(response.body).toHaveProperty('refresh_token_expires_in');
      expect(response.body).toHaveProperty('access_token');
      expect(response.body).toHaveProperty('access_token_expires_in');
    });

    it('should fail as the token should be blacklisted', async () => {
      const response = await request(app).post(uri).send({
        refresh_token: token,
      });

      expect(response.status).toBe(400);
    });
  });

  describe('/api/v1/auth/verify', () => {
    const uri = '/api/v1/auth/verify';

    it('should successfully verify access token', async () => {
      let response = await login();

      expect(response.body).toHaveProperty('access_token');
      const access_token = response.body.access_token;

      response = await request(app).post(uri).send({
        access_token,
      });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('user_id');
    });
  });

  describe('/api/v1/auth/revoke', () => {
    const uri = '/api/v1/auth/revoke';
    it('should successfully revoke a token', async () => {
      let response = await login();

      const {refresh_token} = response.body;

      response = await request(app).post(uri).send({
        refresh_token,
      });

      expect(response.status).toBe(200);
    });
  });
});
