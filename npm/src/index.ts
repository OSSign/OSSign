import { Exec, SigningParameters } from './exec';
import { DownloadBinary, DownloadBinarySync, ossignInPath } from './download';
import { logger } from './tools';
import execSync from 'child_process';

async function Sign(file: string, outFile: string = "", type: string = "pecoff", configPath: string = "" ) {
    logger('Starting asynchronous sign operation');

    // Validate input
    if (!file) {
        throw new Error('Input file is required');
    }

    if (!type) {
        throw new Error('Signing type is required');
    }
   
    logger('Downloading ossign binary for signing');
    let toolPath = await DownloadBinary();

    if (ossignInPath()) {
        logger('Using ossign from PATH after download');
        toolPath = process.platform == "win32" ? "ossign.exe" : "ossign";
    } else {
        logger(`Using downloaded ossign binary at ${toolPath}`);
    }

    const params: SigningParameters = {
        type: type as 'pecoff' | 'msi' | 'authenticode' | 'dmg' | 'auto',
        inputFile: file,
    };

    if (outFile) {
        params.outputFile = outFile;
    }

    if (configPath) {
        params.configFile = configPath;
    } else if (process.env.OSSIGN_CONFIG === undefined && process.env.OSSIGN_CONFIG_BASE64 === undefined) {
        throw new Error('Either configPath or OSSIGN_CONFIG/OSSIGN_CONFIG_BASE64 environment variable must be provided');
    }

    params.binaryPath = toolPath;

    return Exec(params);
}

function GetSignerFunction(type: string = "pecoff", configPath: string = "") {
    return async (path: string) => {
        return await Sign(path, path, type, configPath);
    }
}

function SignSync(file: string, outFile: string = "", type: string = "pecoff", configPath: string = "" ) {
    logger('Starting synchronous sign operation');

    // Validate input
    if (!file) {
        throw new Error('Input file is required');
    }

    if (!type) {
        throw new Error('Signing type is required');
    }
   
    logger('Downloading ossign binary for signing');
    let toolPath = DownloadBinarySync();

    if (ossignInPath()) {
        logger('Using ossign from PATH after download');
        toolPath = process.platform == "win32" ? "ossign.exe" : "ossign";
    } else {
        logger(`Using downloaded ossign binary at ${toolPath}`);
    }

    const params: SigningParameters = {
        type: type as 'pecoff' | 'msi' | 'authenticode' | 'dmg' | 'auto',
        inputFile: file,
    };

    if (outFile) {
        params.outputFile = outFile;
    }

    if (configPath) {
        params.configFile = configPath;
    } else if (process.env.OSSIGN_CONFIG === undefined && process.env.OSSIGN_CONFIG_BASE64 === undefined) {
        throw new Error('Either configPath or OSSIGN_CONFIG/OSSIGN_CONFIG_BASE64 environment variable must be provided');
    }

    params.binaryPath = toolPath;

    return Exec(params);
}

function GetSignerFunctionSync(type: string = "pecoff", configPath: string = "") {
    return (path: string) => {
        return SignSync(path, path, type, configPath);
    }
}


export {
  SigningParameters,
  DownloadBinary,
  DownloadBinarySync,
  Exec,
  Sign,
  SignSync,
  GetSignerFunction,
  GetSignerFunctionSync
}