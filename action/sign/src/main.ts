import * as core from "@actions/core";
import * as github from "@actions/github";
import * as toolcache from '@actions/tool-cache';
import { InstallOssign } from "./tool.ts";
import * as fs from "fs/promises";

const winPath = process.env["ProgramFiles"] ? `${process.env["ProgramFiles"]}\\ossign\\ossign.exe` : "C:\\Program Files\\ossign\\ossign.exe";
const linuxPath = "/usr/local/bin/ossign";

// async function CheckWorkflow(username: string, token: string, id: string) : Promise<WorkflowStatusResponse> {
//     core.info(`Checking workflow status for ID ${id}...`);

//     const response = await CallApi(`check/${username}/${id}`, undefined, token);

//     return response;
// }

async function InstallConfig() : Promise<string> {
    const config = core.getInput("config");

    if (!config || config.trim() === "") {
        throw new Error("Config is required");
    }

    const platform = process.platform;

    if (platform === "win32") {
        const configPath = `${process.env["ProgramData"]}\\ossign\\config.yaml`;
        core.info(`Writing config to ${configPath}...`);3
        await fs.mkdir(`${process.env["ProgramData"]}\\ossign`, { recursive: true });
        await fs.writeFile(configPath, config);
        // await require("fs").promises.mkdir(`${process.env["ProgramData"]}\\ossign`, { recursive: true });
        // await require("fs").promises.writeFile(configPath, config);
        return configPath;
    } else if (platform === "linux" || platform === "darwin") {
        const configPath = "/etc/ossign/config.yaml";
        core.info(`Writing config to ${configPath}...`);
        await fs.mkdir("/etc/ossign", { recursive: true });
        await fs.writeFile(configPath, config);
        // // await require("fs").promises.mkdir("/etc/ossign", { recursive: true });
        // await require("fs").promises.writeFile(configPath, config);
        return configPath;
    } else {
        throw new Error(`Unsupported platform: ${platform}`);
    }
}

   
export async function run() {
    const config = core.getInput("config");
    const installOnly = core.getInput("install_only").toLowerCase() === "true";

    let configPath = "";

    if (config && config.trim() !== "") {
        core.info("Using provided ossign config");
        configPath = await InstallConfig();
    }

    const binaryPath = InstallOssign();
    if (installOnly) {
        core.info("OSSign Binary has been successfully installed");
        core.setOutput("ossign_path", binaryPath);
        core.setOutput("config_path", configPath);
        return;
    }

    core.setFailed("Signing not yet implemented");

//     const inputFile = core.getInput("inputFile");
//     const outputFile = core.getInput("outputFile");
//     const fileType = core.getInput("fileType");




//     const username = core.getInput("username");
//     const token = core.getInput("token");
//     const dispatch_only = core.getInput("dispatch_only").toLowerCase() === "true";
//     const single_check = core.getInput("single_check");

//     if (!username || username.trim() === "") {
//         core.setFailed("Username is required");
//         return;
//     }

//     if (!token || token.trim() === "") {
//         core.setFailed("Token is required");
//         return;
//     }
//   core.setOutput("finished", true);
//     core.info(`Triggering workflow dispatch for ${ref_name} in ${github.context.repo.repo}...`);
// //             return true;
//     // core.info("Workflow not completed yet.");
//         core.setOutput("signed_artifacts", "");
//         core.setOutput("finished", false);
}