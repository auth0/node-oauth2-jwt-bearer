import express from './express-api';
import playground from './playground';

playground.listen(3000, () =>
  console.log('Playground app at http://localhost:3000')
);
express.listen(3001, () => console.log('Express API at http://localhost:3001'));
