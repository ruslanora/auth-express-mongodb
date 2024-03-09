import bcrypt from 'bcrypt';
import mongoose, {Document, Schema, Types} from 'mongoose';

export type UserDocument = Document & {
  _id: Types.ObjectId;
  email: string;
  password: string;
  comparePassword: (canidadte: string) => Promise<boolean>;
};

const UserSchema = new Schema<UserDocument>({
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
});

UserSchema.pre('save', async function (next) {
  const user = this as UserDocument;

  if (!user.isModified('password')) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);
    next();
  } catch (error) {
    return next(error as Error);
  }
});

UserSchema.methods.comparePasswords = function (
  canidadte: string,
): Promise<boolean> {
  return bcrypt.compare(canidadte, this.password);
};

export const User = mongoose.model<UserDocument>('User', UserSchema);
