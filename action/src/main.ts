import * as core from "@actions/core";
import { InstallOssign } from "./tool.ts";
import * as fs from "fs/promises";
import * as exec from "@actions/exec";
import * as glob from "@actions/glob";

async function InstallConfig() : Promise<string> {
    const config = core.getInput("config");

    if (!config || config.trim() === "" || config.length < 10) {
        core.info("No config provided, skipping config installation");
        return "";
    }

    const platform = process.platform;

    let configPath = "";

    if (platform === "win32") {
        configPath = `${process.env["USERPROFILE"]}\\ossign\\config.yaml`;
        core.info(`Writing config to ${configPath}...`);
        await fs.mkdir(`${process.env["USERPROFILE"]}\\ossign`, { recursive: true });
        await fs.writeFile(configPath, config);
    } else {
        configPath = `${process.env["HOME"]}/.ossign/config.yaml`;
        core.info(`Writing config to ${configPath}...`);
        await fs.mkdir(`${process.env["HOME"]}/.ossign`, { recursive: true });
        await fs.writeFile(configPath, config);
    }

    return configPath;
}

   
export async function run() {
    const config = core.getInput("config");
    const installOnly = core.getInput("install_only").toLowerCase() === "true";

    let configPath = "";

    if (config && config.trim() !== "" && installOnly) {
        core.info("Using provided ossign config");
        configPath = await InstallConfig();
    }

    const binaryPath = await InstallOssign();
    core.info("OSSign Binary has been successfully installed");
    core.setOutput("ossignPath", binaryPath);
    core.setOutput("configPath", configPath);

    const resp = await exec.getExecOutput("ossign", ["--help"]);
    if (resp.exitCode !== 0) {
        core.error("ossign --help failed, something went wrong with the installation");
        core.error(resp.stderr);
    }

    if (installOnly) {
        return;
    }

    const fileType = core.getInput("fileType");

    const inputFiles = core.getInput("inputFiles");
    if (inputFiles && inputFiles.trim() !== "") {
        core.info(`Signing multiple files according to glob pattern(s) `+ inputFiles);
        
        const globOptions = {
            followSymbolicLinks: false
        }

        const globber = await glob.create(inputFiles, globOptions);
        for await (const file of globber.globGenerator()) {
            core.info(`Signing file: ${file}`);

            let signcmd = [ file, "-o", file ];
            
            if (fileType.trim() !== "") {
                signcmd.push("-t", fileType);
            } else {
                core.warning("No fileType provided, ossign will attempt to auto-detect the file type");
                signcmd.push("-t", "auto");
            }

            const signResp = await exec.getExecOutput("ossign", signcmd, {
                env: {
                    "OSSIGN_CONFIG": config,
                    "HOME": process.env["HOME"] || "",
                    "USERPROFILE": process.env["USERPROFILE"] || ""
                }
            });
            if (signResp.exitCode !== 0) {
                core.setFailed(`ossign signing failed for file ${file}`);
                core.error(signResp.stderr);
                return;
            }

            core.info(`ossign signing completed successfully for file ${file}`);
            core.info(signResp.stdout);
        }

        core.setOutput("finished", true);
        return;
    }
    
    const inputFile = core.getInput("inputFile");
    const outputFile = core.getInput("outputFile");

    let signcmd = [ inputFile ];
    if (outputFile.trim() !== "") {
        signcmd.push("-o", outputFile);
    }

    if (fileType.trim() !== "") {
        signcmd.push("-t", fileType);
    }

    core.info(`Signing file ${inputFile}...`);
    const signResp = await exec.getExecOutput("ossign", signcmd, {
       env: {
            "OSSIGN_CONFIG": config,
            "HOME": process.env["HOME"] || "",
            "USERPROFILE": process.env["USERPROFILE"] || ""
        }
    });
    if (signResp.exitCode !== 0) {
        core.setFailed("ossign signing failed");
        core.error(signResp.stderr);
        return;
    }

    core.info("ossign signing completed successfully");
    core.info(signResp.stdout);
    core.setOutput("signedFile", outputFile.trim() === "" ? inputFile : outputFile);
    core.setOutput("finished", true);
}