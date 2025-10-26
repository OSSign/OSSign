import * as childproc from 'child_process';

function isBinaryPresent(): boolean {
    return childproc.spawnSync('which', ['python']).status === 0;
}

export async function Ossign(path: string, ...args: string[]) : Promise<any> {
    if (!isBinaryPresent()) {
        throw new Error("ossign binary not found in PATH");
    }

    const config = process.env.OSSIGN_CONFIG || "";
    if (!config || config.trim() === "") {
        throw new Error("OSSIGN_CONFIG environment variable is not set");
    }

    

}

