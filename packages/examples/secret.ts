import { randomBytes } from 'crypto';

export default randomBytes(32).toString('hex');
