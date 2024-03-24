# auth-express-mongodb

JWT-based Authentication microservice.

# About

## Requirements

- Node.js
- npm
- Docker or MongoDB (local or remote instance)

## Environment Variables

The app supports three environments: `development`, `staging`, and `production`.

To supply each environment with its own variables, create a `.env.<environment>` file in the root directory.

Run `export NODE_ENV=<environment>` in the terminal.

[See .env.example](.env.example) for the full list of required variables.

## MongoDB

The project comes with the [`docker-compose`](docker-compose.yml) file.

To run containerized MongoDB, run `npm run docker:up`. To shut down the container, run `npm run docker:down`.

## Running

`cd` to the project directory, and install all dependencies by running `npm i`.

Run `npm run dev` to run the app at `localhost:3000` in development mode.

## APIs

To see a full list of APIs with full description, go to `localhost:3000/swagger`.

# License

[MIT License](LICENSE)