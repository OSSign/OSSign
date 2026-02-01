import * as child_process from 'child_process';

export type SigningParameters = {
    binaryPath?: string;
    type: 'pecoff' | 'msi' | 'authenticode' | 'dmg' | 'auto';
    inputFile: string;
    outputFile?: string;
    configFile?: string;
}

export function Exec(params: SigningParameters): string {
    console.log('Starting synchronous exec operation');

    // Validate input
    if (!params.inputFile) {
        throw new Error('Input file is required');
    }

    if (!params.type) {
        throw new Error('Signing type is required');
    }

    // Run the OSSign Command
    let paramsList = [];

    if (params.type) {
        paramsList.push('-t', params.type);
    }

    if (params.outputFile) {
        paramsList.push('-o', params.outputFile);
    }

    if (params.configFile) {
        paramsList.push('-c', params.configFile);
    }

    paramsList.push(params.inputFile);

    const binaryPath = params.binaryPath || ( process.platform === 'win32' ? 'ossign.exe' : 'ossign');
    console.log(`Executing command: ${binaryPath} ${paramsList.join(' ')}`);

    try {
        const output = child_process.execFileSync(binaryPath, paramsList, { encoding: 'utf8' });
        console.log('Command output:', output);
        return output;
    } catch (err) {
        throw new Error(`Signing operation failed: ${err}`);
    }
}