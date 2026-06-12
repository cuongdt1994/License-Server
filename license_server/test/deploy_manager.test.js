'use strict';

const assert = require('assert');
const { createDeployManager } = require('../deploy_manager');

(async () => {
    const commands = [];
    const manager = createDeployManager({
        cwd: 'C:\\app',
        runCommand: async (cmd, args) => {
            commands.push([cmd, args]);
            return { code: 0, stdout: `${cmd} ok`, stderr: '' };
        },
    });

    const result = await manager.runUpdate();
    assert.equal(result.ok, true);
    assert.deepEqual(commands.map(([cmd]) => cmd), ['git', 'npm.cmd']);
    assert.deepEqual(commands[0][1], ['pull', '--ff-only']);
    assert.deepEqual(commands[1][1], ['run', 'pm2:restart']);
    assert.equal(manager.status().last.ok, true);

    let release;
    const locked = createDeployManager({
        cwd: 'C:\\app',
        runCommand: () => new Promise(resolve => { release = () => resolve({ code: 0, stdout: 'done', stderr: '' }); }),
    });
    const first = locked.runUpdate();
    await new Promise(resolve => setTimeout(resolve, 5));
    await assert.rejects(() => locked.runUpdate(), /Deployment is already running/);
    release();
    await first;

    console.log('deploy manager tests passed');
})().catch(err => {
    console.error(err);
    process.exit(1);
});
