const execSync = require('child_process').execSync

const release = process.argv[2] || ''
const target = process.argv[3] || ''
const build = process.argv[4] || ''

execSync('napi build --platform ' + release + ' ' + target + ' ' + build, {
  stdio: [0, 1, 2, 3, 4],
})
execSync('prettier ./index.* --write', { stdio: [0, 1, 2, 3, 4] })
