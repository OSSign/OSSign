import { Sign } from './index';
import * as process from 'process';

Sign(process.argv[2], process.argv[3] || undefined, process.argv[4] || undefined, process.argv[5] || undefined).then(() => {
    process.exit(0);
}).catch((err) => {
    console.error('Error during signing:', err);
    process.exit(1);
});