export class CaStratedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CaStratedError';
  }
}
