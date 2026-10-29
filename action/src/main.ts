import * as core from "@actions/core";
import { getDefaultConfigPath, InstallOssign } from "./tool.ts";
import * as fs from "fs/promises";
import * as exec from "@actions/exec";
//import * as glob from "@actions/glob";
import { Glob } from "glob";


async function makeTrustedConfig() : Promise<string> {
    const trustedSigningServer = core.getInput("trustedSigningServer");
    const trustedSigningKey = core.getInput("trustedSigningKey");
    const trustedSigningTimestamper = core.getInput("trustedSigningTimestamper");
    const trustedSigningMsTimestamper = core.getInput("trustedSigningMsTimestamper");

    if (trustedSigningServer == "" || trustedSigningKey == "" || trustedSigningTimestamper == "" || trustedSigningMsTimestamper == "") {
        throw new Error("Trusted signing configuration is incomplete");
    }

    return JSON.stringify({
        "tokenType": "ossignServer",
        "ossignServer": {
            "url": trustedSigningServer,
            "key": trustedSigningKey,
            "provider": "github"
        },
        "timestampUrl": trustedSigningTimestamper,
        "msTimestampUrl": trustedSigningMsTimestamper
    });
}

async function InstallConfig(config: string) : Promise<string> {
    if (!config || config.trim() === "" || config.length < 10) {   
        core.info("No config provided, skipping config installation");
        return "";
    }

    const platform = process.platform;

    let configPath = getDefaultConfigPath();

    if (platform === "win32") {
        await fs.mkdir(`${process.env["USERPROFILE"]}\\ossign`, { recursive: true });
        await fs.writeFile(configPath, config);
    } else {
        await fs.mkdir(`${process.env["HOME"]}/.ossign`, { recursive: true });
        await fs.writeFile(configPath, config);
    }

    return configPath;
}

   
export async function run() {
    var config = core.getInput("config");
    const installOnly = core.getInput("installOnly").toLowerCase() === "true";
    
    const trustedSigning = core.getInput("trustedSigning").toLowerCase() === "true";
    if (trustedSigning) {
        core.info("Trusted signing is enabled, writing out configuration...")
        config = await makeTrustedConfig();
    }

    // Signing through an OSSign Server needs the job's OIDC token. GitHub only
    // provides it when the job declares `permissions: id-token: write`; fail
    // here with a clear message instead of a confusing error from the CLI.
    const usesServer = trustedSigning || /"tokenType"\s*:\s*"ossignServer"|tokenType:\s*ossignServer/.test(config);
    if (usesServer && !process.env["ACTIONS_ID_TOKEN_REQUEST_URL"]) {
        core.setFailed("This job signs through an OSSign Server, which needs an OIDC token, but the job has no `permissions: id-token: write`. Add it to the job (or workflow) permissions and run again.");
        return;
    }

    let configPath = "";

    if (config && config.trim() !== "" && installOnly) {
        core.info("Using provided ossign config");
        configPath = await InstallConfig(config);
    } else if ((!config || config.trim() !== "")) {
        configPath = getDefaultConfigPath();
        try {
            const configContent = await fs.readFile(configPath, "utf-8");
            if (!configContent || configContent.trim() === "") {
                core.warning(`Config file at ${configPath} is empty`);
            } else {
                core.info(`Using existing config file at ${configPath}`);
                config = configContent;
            }
        } catch (err) {
            core.warning(`Failed to read config file at ${configPath}: ${err}`);
        }
    }

    const binaryPath = await InstallOssign();
    core.info("OSSign Binary has been successfully installed");
    core.setOutput("ossignPath", binaryPath);
    core.setOutput("configPath", configPath);

    core.info("Verifying ossign installation by running 'ossign --help'...");

    const resp = await exec.getExecOutput("ossign", ["--help"]);
    if (resp.exitCode !== 0) {
        core.error("ossign --help failed, something went wrong with the installation");
        core.error(resp.stderr);
    }

    if (installOnly) {
        core.info("installOnly is set to true, skipping signing step");
        core.setOutput("finished", true);
        return;
    }

    core.info(`installOnly was not set (${installOnly}), running OSSign to sign the provided file(s)`);

    const fileType = core.getInput("fileType");

    const inputFiles = core.getInput("inputFiles");
    if (inputFiles && inputFiles.trim() !== "") {
        core.info(`Signing multiple files according to glob pattern(s) `+ inputFiles);

        if (core.isDebug()) {
            core.debug("Debug logging is enabled");
            core.debug("Working directory: " + process.cwd());
            core.debug("Input files glob pattern: " + inputFiles);
            core.debug("File type: " + fileType);
            core.debug("Current dir file list:");
            const dirFiles = await fs.readdir(process.cwd());
            for (const f of dirFiles) {
                core.debug(` - ${f}`);
            }
        }
        
        // Replace GHA glob implementation because it stopped working on Windows
        // see https://github.com/actions/toolkit/issues/2085
        // const globOptions = {
        //     followSymbolicLinks: false
        // };

        // var globs: string[] = [];


        // try {

        //     // const globber = await glob.create(inputFiles, globOptions);
        //     globs = await globber.glob();
        // } catch (error) {
        //     core.setFailed(`Failed to process glob pattern(s) ${inputFiles}: ${error}`);
        //     return;
        // }

        var globs: string[] = [];

        const splits = inputFiles.replaceAll("\r\n", "\n").split("\n");
        for (const pattern of splits) {
            if (pattern.trim() === "") {
                continue;
            }
            core.info("Matching glob pattern: " + pattern);
            globs.push(pattern);
        }

        const globber = new Glob(globs, { follow: false });

        // core.info(`Found ${globs.length} file(s) to sign: ${globs.join(", ")}`);

        for (const file of globber) {
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
                    "USERPROFILE": process.env["USERPROFILE"] || "",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": process.env["ACTIONS_ID_TOKEN_REQUEST_URL"] || "",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] || "",
                    "OSSIGN_ID_TOKEN": process.env["OSSIGN_ID_TOKEN"] || ""
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
            "USERPROFILE": process.env["USERPROFILE"] || "",
            "ACTIONS_ID_TOKEN_REQUEST_URL": process.env["ACTIONS_ID_TOKEN_REQUEST_URL"] || "",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] || "",
            "OSSIGN_ID_TOKEN": process.env["OSSIGN_ID_TOKEN"] || ""
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