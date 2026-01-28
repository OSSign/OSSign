import { getToolName, getToolUrl, isGithubActions, logger } from './tools';
import { execSync } from 'child_process';
import * as core from "@actions/core";
import * as toolcache from '@actions/tool-cache';
import * as fs from 'fs';
import * as os from 'os';

export function ossignInPath(): boolean {
    const binary = process.platform == "win32" ? "ossign.exe" : "ossign";
    const whichCmd = process.platform == "win32" ? "where.exe" : "which";
    
    try {
        execSync(`${whichCmd} ${binary}`, { stdio: 'ignore' });
        logger(`${binary} found in PATH`);
        return true;
    } catch (error) {
        logger(`${binary} not found in PATH`);
        return false;
    }
}


export async function DownloadBinary(version: string = "latest"): Promise<string> {
    const binary = getToolName();
    const url = getToolUrl(version);

    logger(`Downloading binary from ${url}`);

    if (isGithubActions()) {
        const inCache = toolcache.find(binary, version, process.arch);
        if (inCache) {
            logger(`Found ${binary} in cache at ${inCache}`);
            core.addPath(inCache);
            return inCache;
        }

        logger(`Downloading ${binary} from ${url}...`);
        const downloadPath = await toolcache.downloadTool(url);
        if (!downloadPath) {
            throw new Error(`Failed to download ${binary}`);
        }

        const cachePath = await toolcache.cacheFile(downloadPath, process.platform == "win32" ? "ossign.exe" : "ossign", binary, version, process.arch);
        if (!cachePath) {
            throw new Error(`Failed to cache ${binary}`);
        }

        if (process.platform !== "win32") {
            fs.chmodSync(`${cachePath}/ossign`, 0o755);
        }

        core.addPath(cachePath);
        return process.platform == "win32" ? `ossign.exe` : `ossign`;
    }

    const tempDir = fs.mkdtempSync(`${os.tmpdir()}/${process.platform}-${process.arch}-`);
    const targetPath = `${tempDir}/${process.platform == "win32" ? "ossign.exe" : "ossign"}`;

    logger(`Downloading ${binary} to temporary path ${targetPath}...`);

    const downloadPath = await toolcache.downloadTool(url, targetPath);
    if (!downloadPath) {
        throw new Error(`Failed to download ${binary}`);
    }

    if (process.platform !== "win32") {
        fs.chmodSync(downloadPath, 0o755);
    }

    logger(`${binary} downloaded to ${downloadPath}`);

    return downloadPath;
}

function deasync<T>(promise: Promise<T>): T {
    let isDone = false;
    let result: T;
    let error: any;

    promise.then(res => {
        result = res;
        isDone = true;
    }).catch(err => {
        error = err;
        isDone = true;
    });

    // Block the event loop until the promise is resolved
    require('deasync').loopWhile(() => !isDone);

    if (error) {
        throw error;
    }

    return result!;
}

export function DownloadBinarySync(version: string = "latest"): string {
    return deasync(DownloadBinary(version));
}