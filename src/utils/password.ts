import zxcvbn from 'zxcvbn';

const WEAKNESS_THRESHOLD = 3;

export const isWeak = (
  password: string,
  userInput: string[],
): string | null => {
  const result = zxcvbn(password, userInput);

  if (result.score < WEAKNESS_THRESHOLD) {
    return result.feedback.suggestions.join(' ') || 'Password is too weak';
  }

  return null;
};
