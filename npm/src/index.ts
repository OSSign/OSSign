import { Exec, SigningParameters } from './exec';
import { DownloadBinary, DownloadBinarySync, ossignInPath } from './download';
import { logger } from './tools';

async function Sign(file: string, outFile: string = "", type: string = "pecoff", configPath: string = "" ) {
    logger('Starting asynchronous sign operation');

    // Validate input
    if (!file) {
        throw new Error('Input file is required');
    }

    if (!type) {
        throw new Error('Signing type is required');
    }

    let toolPath = '';

    if (ossignInPath()) {
        logger('Using ossign from PATH');
        toolPath = process.platform == "win32" ? "ossign.exe" : "ossign";
    } else {
        logger('Downloading ossign binary for signing');
        toolPath = await DownloadBinary();

        if (ossignInPath()) {
            logger('Using ossign from PATH after download');
            toolPath = process.platform == "win32" ? "ossign.exe" : "ossign";
        } else {
            logger(`Using downloaded ossign binary at ${toolPath}`);
        }
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

    return await Exec(params);
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

    let toolPath = '';

    if (ossignInPath()) {
        logger('Using ossign from PATH');
        toolPath = process.platform == "win32" ? "ossign.exe" : "ossign";
    } else {
        logger('Downloading ossign binary for signing');
        toolPath = DownloadBinarySync();
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
    return async (file: string) => {
        return await Sign(file, file, type, configPath);
    }
}

function GetSignerFunctionSync(type: string = "pecoff", configPath: string = "") {
    return (file: string) => {
        return SignSync(file, file, type, configPath);
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