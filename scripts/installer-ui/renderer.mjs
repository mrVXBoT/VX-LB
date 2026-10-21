import { cliui } from '@poppinss/cliui'

const [command, ...args] = process.argv.slice(2)
const animated = process.stdout.isTTY && process.env.TERM !== 'dumb'
const ui = cliui({ mode: animated && !('NO_COLOR' in process.env) ? 'normal' : 'silent' })
if (command === 'probe') {
  // Importing the bundle checks runtime compatibility without emitting anything.
} else if (command === 'plan') {
  ui.instructions()
    .heading('VX-LB / Installation plan')
    .add(`Directory  ${args[0]}`)
    .add('Payload    Verified offline wheels + engine depot')
    .add('Flow       Verify > Install > Configure > Ready')
    .render()
} else if (command === 'done') {
  ui.logger.success(`${args[0]} (${args[1]}s)`)
} else if (command === 'success') {
  ui.sticker().heading('VX-LB is ready')
    .add('Management panel      vx-lb')
    .add('Web dashboard         vx-lb --web')
    .add('Dashboard password    vx-lb --set-web-password')
    .add('Watchdog status       sudo systemctl status vx-lb-watchdog')
    .render()
  ui.logger.info(`Installation: ${args[0]}`)
  ui.logger.info(`Command: ${args[1]}`)
  ui.logger.info(`Full log: ${args[2]}`)
} else {
  throw new Error(`Unknown installer UI command: ${command}`)
}
