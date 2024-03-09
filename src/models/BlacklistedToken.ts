import mongoose, {Document, Schema} from 'mongoose';

export type BlacklistedTokenDocument = Document & {
  token: string;
  expiresAt: Date;
};

const BlacklistedTokenSchema = new Schema<BlacklistedTokenDocument>({
  token: {
    type: String,
    required: true,
    unique: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
});

BlacklistedTokenSchema.index({expiresAt: 1}, {expireAfterSeconds: 0});

export const BlacklistedToken = mongoose.model<BlacklistedTokenDocument>(
  'BlacklistedToken',
  BlacklistedTokenSchema,
);
