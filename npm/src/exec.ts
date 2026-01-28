import * as fs from 'fs';
import * as child_process from 'child_process';
import * as os from 'os';
import * as path from 'path';

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
    } else if (process.env.OSSIGN_CONFIG !== undefined || process.env.OSSIGN_CONFIG_BASE64 !== undefined) {
        // Create a temp file for the config
        const tempConfigPath = path.join(os.tmpdir(), `ossign_config_${Date.now()}.json`);

        if (process.env.OSSIGN_CONFIG !== undefined) {
            try {
                fs.writeFileSync(tempConfigPath, process.env.OSSIGN_CONFIG, 'utf8');
            } catch (err) {
                throw new Error(`Failed to write OSSIGN_CONFIG to temp file: ${err}`);
            }
        } else {
            const decodedConfig = Buffer.from(process.env.OSSIGN_CONFIG_BASE64!, 'base64').toString('utf8');
            try {
                fs.writeFileSync(tempConfigPath, decodedConfig, 'utf8');
            } catch (err) {
                throw new Error(`Failed to write OSSIGN_CONFIG_BASE64 to temp file: ${err}`);
            }
        }

        paramsList.push('-c', tempConfigPath);
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