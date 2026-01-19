/**
 * Node-RED SFTP Node
 * 
 * A Node-RED node for SFTP file operations including list, get, put, delete,
 * mkdir, and rmdir operations.
 * 
 * @module node-red-contrib-better-sftp
 * @author Jordan Vohwinkel <jvohwinkel@gmail.com>
 * @license MIT
 * 
 * CHANGELOG (Improvements):
 * - Fixed: Path handling now works correctly across Windows and Linux
 * - Fixed: Concurrent connections no longer overwrite each other (uses message-scoped state)
 * - Fixed: rmdir operation was incorrectly calling mkdir
 * - Fixed: Removed unreachable code and undefined variable references
 * - Fixed: Proper connection cleanup without duplicate end() calls
 * - Added: Comprehensive JSDoc documentation
 * - Added: Cross-platform path utilities
 * - Added: Connection state tracking to prevent double-close
 * - Added: Better error messages and logging
 */

'use strict';

const fs = require('fs');
const path = require('path');
const Client = require('ssh2-sftp-client');

/**
 * Utilities for handling paths in SFTP operations.
 * SFTP always uses POSIX-style paths (forward slashes) regardless of local OS.
 */
const PathUtils = {
    /**
     * Joins path segments using POSIX separators for remote SFTP paths.
     * SFTP servers always expect forward slashes, even when client is Windows.
     * 
     * @param {...string} segments - Path segments to join
     * @returns {string} Joined path with forward slashes
     * @example
     * PathUtils.joinRemote('/home/user', 'files', 'document.txt')
     * // Returns: '/home/user/files/document.txt'
     */
    joinRemote: function (...segments) {
        // Filter out empty segments and join with forward slash
        const filtered = segments.filter(s => s && s.trim() !== '');
        if (filtered.length === 0) return './';
        
        let result = filtered.join('/');
        // Normalize multiple slashes but preserve leading slash
        result = result.replace(/\/+/g, '/');
        return result;
    },

    /**
     * Normalizes a remote SFTP path to use forward slashes.
     * Handles Windows-style backslashes that might be passed in.
     * 
     * @param {string} remotePath - The path to normalize
     * @returns {string} Normalized path with forward slashes
     */
    normalizeRemote: function (remotePath) {
        if (!remotePath) return './';
        // Replace backslashes with forward slashes for SFTP
        return remotePath.replace(/\\/g, '/').replace(/\/+/g, '/');
    },

    /**
     * Joins path segments for local filesystem using OS-appropriate separators.
     * Uses Node.js path.join for proper cross-platform handling.
     * 
     * @param {...string} segments - Path segments to join
     * @returns {string} Joined path with OS-appropriate separators
     */
    joinLocal: function (...segments) {
        return path.join(...segments);
    },

    /**
     * Resolves a local path to an absolute path.
     * 
     * @param {string} localPath - The path to resolve
     * @returns {string} Absolute path
     */
    resolveLocal: function (localPath) {
        return path.resolve(localPath);
    }
};

/**
 * Main module export for Node-RED
 * @param {object} RED - Node-RED runtime object
 */
module.exports = function (RED) {

    /**
     * SFTP Configuration Node
     * Stores connection configuration including host, port, credentials, and algorithms.
     * This is a config node that can be shared across multiple SFTP operation nodes.
     * 
     * @class SFtpNode
     * @param {object} n - Node configuration from Node-RED editor
     */
    function SFtpNode(n) {
        RED.nodes.createNode(this, n);
        
        /** @type {boolean} Indicates if the configuration is valid */
        this.valid = true;
        
        /** @type {string|Buffer|undefined} Private key for authentication */
        this.key = undefined;

        // Handle private key from file path (local files option)
        const keyPath = (n.key || '').trim();
        if (keyPath.length > 0) {
            try {
                this.key = fs.readFileSync(keyPath);
            } catch (err) {
                this.valid = false;
                this.error(`Failed to read private key file: ${err.message}`);
                return;
            }
        } else if (this.credentials && this.credentials.keydata) {
            // Handle private key from uploaded data
            this.key = this.credentials.keydata;
        }

        /**
         * Connection options object
         * Note: Credentials (username, password, passphrase) are stored separately
         * in this.credentials and should be accessed from there
         */
        this.options = {
            nname: n.nname || '',
            host: n.host || 'localhost',
            port: parseInt(n.port, 10) || 22,
            tryKeyboard: n.tryKeyboard || false,
            algorithms_kex: n.algorithms_kex || 'ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1',
            algorithms_cipher: n.algorithms_cipher || 'aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm,aes128-gcm@openssh.com,aes256-gcm,aes256-gcm@openssh.com',
            algorithms_serverHostKey: n.algorithms_serverHostKey || 'ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521',
            algorithms_hmac: n.algorithms_hmac || 'hmac-sha2-256,hmac-sha2-512,hmac-sha1',
            algorithms_compress: n.algorithms_compress || 'none,zlib@openssh.com,zlib'
        };
    }

    // Register the configuration node type with credentials schema
    RED.nodes.registerType('sftp', SFtpNode, {
        credentials: {
            username: { type: 'text' },
            password: { type: 'password' },
            keydata: { type: 'text' },
            passphrase: { type: 'password' }
        }
    });

    /**
     * SFTP Operation Node
     * Performs SFTP operations (list, get, put, delete, mkdir, rmdir).
     * Each incoming message triggers a new connection to handle the operation,
     * ensuring concurrent messages don't interfere with each other.
     * 
     * @class SFtpInNode
     * @param {object} n - Node configuration from Node-RED editor
     */
    function SFtpInNode(n) {
        RED.nodes.createNode(this, n);
        
        const node = this;
        
        // Store node configuration (these are defaults, can be overridden by msg)
        node.nname = n.nname;
        node.sftp = n.sftp;
        node.operation = n.operation;
        node.filename = n.filename || '';
        node.localFilename = n.localFilename || '';
        node.workdir = n.workdir || './';
        
        // Get reference to the configuration node
        node.sftpConfig = RED.nodes.getNode(node.sftp);

        // Validate configuration exists
        if (!node.sftpConfig) {
            node.error('No SFTP configuration found. Please configure an SFTP server.');
            node.status({ fill: 'red', shape: 'ring', text: 'no config' });
            return;
        }

        // Validate configuration is valid (key file loaded successfully, etc.)
        if (!node.sftpConfig.valid) {
            node.error('SFTP configuration is invalid. Check server configuration.');
            node.status({ fill: 'red', shape: 'ring', text: 'invalid config' });
            return;
        }

        // Validate credentials are present
        if (!node.sftpConfig.credentials || !node.sftpConfig.credentials.username) {
            node.error('Username not configured. Add username in SFTP server configuration.');
            node.status({ fill: 'red', shape: 'ring', text: 'no username' });
            return;
        }

        /**
         * Creates an error object with context for Node-RED error handling
         * 
         * @param {Error|string} err - The error that occurred
         * @param {object} msg - The message that triggered the error
         * @param {object} config - The connection configuration used
         * @returns {object} Enhanced message object with error details
         */
        function createErrorMessage(err, msg, config) {
            const errorMessage = err instanceof Error ? err.message : String(err);
            msg.error = {
                message: errorMessage,
                source: {
                    id: node.id,
                    type: 'sftp in',
                    name: node.name || 'sftp',
                    host: config ? config.host : 'unknown',
                    port: config ? config.port : 'unknown'
                }
            };
            return msg;
        }

        /**
         * Safely closes an SFTP connection
         * Tracks connection state to prevent double-close errors
         * 
         * @param {Client} sftp - The SFTP client instance
         * @param {boolean} isConnected - Reference to connection state
         * @returns {Promise<void>}
         */
        async function safeClose(sftp, connectionState) {
            if (connectionState.connected) {
                connectionState.connected = false;
                try {
                    await sftp.end();
                } catch (closeErr) {
                    // Ignore close errors - connection may already be closed
                    node.debug(`Connection close note: ${closeErr.message}`);
                }
            }
        }

        /**
         * Message input handler
         * Creates a new SFTP connection for each message to ensure
         * concurrent operations don't interfere with each other.
         */
        node.on('input', async function (msg, send, done) {
            // For Node-RED 0.x compatibility
            send = send || function () { node.send.apply(node, arguments); };
            done = done || function (err) { if (err) node.error(err, msg); };

            // Create message-scoped copies of all configuration
            // This prevents concurrent messages from overwriting each other's settings
            const msgConfig = {
                workdir: PathUtils.normalizeRemote(msg.workdir || node.workdir || './'),
                filename: msg.filename || node.filename || '',
                localFilename: msg.localFilename || node.localFilename || '',
                operation: msg.operation || node.operation
            };

            // Create message-scoped connection settings
            // Do NOT modify node.sftpConfig.options - that would affect other messages
            const conSettings = {
                host: msg.host || node.sftpConfig.options.host,
                port: msg.port || node.sftpConfig.options.port,
                username: msg.user || node.sftpConfig.credentials.username,
                password: msg.password || node.sftpConfig.credentials.password || '',
                privateKey: node.sftpConfig.key || '',
                passphrase: node.sftpConfig.credentials.passphrase || '',
                tryKeyboard: node.sftpConfig.options.tryKeyboard,
                algorithms: {
                    kex: node.sftpConfig.options.algorithms_kex.split(',').map(s => s.trim()),
                    cipher: node.sftpConfig.options.algorithms_cipher.split(',').map(s => s.trim()),
                    serverHostKey: node.sftpConfig.options.algorithms_serverHostKey.split(',').map(s => s.trim()),
                    hmac: node.sftpConfig.options.algorithms_hmac.split(',').map(s => s.trim()),
                    compress: node.sftpConfig.options.algorithms_compress.split(',').map(s => s.trim())
                }
            };

            // Create a new SFTP client for this message
            // Each message gets its own connection to support concurrency
            const sftp = new Client();
            
            // Track connection state to prevent double-close
            const connectionState = { connected: false };

            node.status({ fill: 'blue', shape: 'dot', text: 'connecting...' });

            try {
                // Set up keyboard-interactive authentication if enabled
                if (conSettings.tryKeyboard) {
                    sftp.on('keyboard-interactive', (name, instructions, instructionsLang, prompts, finish) => {
                        finish([conSettings.password]);
                    });
                }

                // Connect to SFTP server
                await sftp.connect(conSettings);
                connectionState.connected = true;
                node.status({ fill: 'green', shape: 'dot', text: 'connected' });

                // Execute the requested operation
                switch (msgConfig.operation) {
                    
                    /**
                     * LIST OPERATION
                     * Lists contents of a directory on the SFTP server
                     * Input: msg.payload (optional) - directory path to list
                     * Output: msg.payload - array of file/directory objects
                     */
                    case 'list': {
                        const listDir = PathUtils.normalizeRemote(
                            msg.payload && typeof msg.payload === 'string' ? msg.payload : msgConfig.workdir
                        );
                        
                        node.status({ fill: 'blue', shape: 'dot', text: `listing ${listDir}` });
                        
                        const fileListing = await sftp.list(listDir);
                        msg.payload = fileListing;
                        msg.directory = listDir;
                        
                        node.status({ fill: 'green', shape: 'dot', text: `listed ${fileListing.length} items` });
                        send(msg);
                        break;
                    }

                    /**
                     * GET OPERATION
                     * Downloads a file from the SFTP server
                     * Input: msg.payload (optional) - full remote path to file
                     * Output: msg.payload - Buffer containing file contents
                     */
                    case 'get': {
                        // Build remote file path
                        let getFilePath;
                        if (msg.payload && typeof msg.payload === 'string') {
                            getFilePath = PathUtils.normalizeRemote(msg.payload);
                        } else {
                            getFilePath = PathUtils.joinRemote(msgConfig.workdir, msgConfig.filename);
                        }
                        
                        node.status({ fill: 'blue', shape: 'dot', text: `downloading ${path.basename(getFilePath)}` });
                        
                        const fileBytes = await sftp.get(getFilePath);
                        msg.payload = fileBytes;
                        msg.remotePath = getFilePath;
                        msg.filename = path.basename(getFilePath);
                        
                        node.status({ fill: 'green', shape: 'dot', text: `downloaded ${msg.filename}` });
                        send(msg);
                        break;
                    }

                    /**
                     * PUT OPERATION
                     * Uploads a file to the SFTP server
                     * Input: msg.payload can be:
                     *   - { localfile: '/path/to/file' } - upload from local file
                     *   - { data: Buffer, filename: 'name.txt', remotefolder: '/path' } - upload buffer
                     *   - Buffer - upload buffer directly (uses configured filename)
                     * Output: msg.payload - upload result string
                     */
                    case 'put': {
                        // Determine filename and remote folder from message or config
                        let putFilename = msgConfig.filename;
                        let putRemoteFolder = msgConfig.workdir;
                        
                        if (msg.payload && typeof msg.payload === 'object' && !Buffer.isBuffer(msg.payload)) {
                            if (msg.payload.filename) putFilename = msg.payload.filename;
                            if (msg.payload.remotefolder) putRemoteFolder = PathUtils.normalizeRemote(msg.payload.remotefolder);
                        }
                        
                        const putFilePath = PathUtils.joinRemote(putRemoteFolder, putFilename);
                        
                        node.status({ fill: 'blue', shape: 'dot', text: `uploading ${putFilename}` });

                        // Handle different payload types
                        if (msg.payload && msg.payload.localfile) {
                            // Upload from local file path
                            const localPath = PathUtils.resolveLocal(msg.payload.localfile);
                            
                            if (!fs.existsSync(localPath)) {
                                throw new Error(`Local file not found: ${localPath}`);
                            }
                            
                            const result = await sftp.fastPut(localPath, putFilePath);
                            msg.payload = result;
                            msg.localPath = localPath;
                            
                        } else if (msg.payload && (msg.payload.data || Buffer.isBuffer(msg.payload))) {
                            // Upload from buffer
                            const dataBuffer = Buffer.isBuffer(msg.payload) ? msg.payload : msg.payload.data;
                            const result = await sftp.put(dataBuffer, putFilePath);
                            msg.payload = result;
                            
                        } else {
                            throw new Error('Invalid payload for PUT operation. Provide localfile path or data buffer.');
                        }
                        
                        msg.remotePath = putFilePath;
                        msg.filename = putFilename;
                        
                        node.status({ fill: 'green', shape: 'dot', text: `uploaded ${putFilename}` });
                        send(msg);
                        break;
                    }

                    /**
                     * DELETE OPERATION
                     * Deletes a file from the SFTP server
                     * Input: msg.payload (optional) - full path to file to delete
                     * Output: msg.payload - deletion result
                     */
                    case 'delete': {
                        let deleteFilePath;
                        if (msg.payload && typeof msg.payload === 'string') {
                            deleteFilePath = PathUtils.normalizeRemote(msg.payload);
                        } else {
                            deleteFilePath = PathUtils.joinRemote(msgConfig.workdir, msgConfig.filename);
                        }
                        
                        if (!deleteFilePath || deleteFilePath === './' || deleteFilePath === '/') {
                            throw new Error('Invalid file path for delete operation');
                        }
                        
                        node.status({ fill: 'blue', shape: 'dot', text: `deleting ${path.basename(deleteFilePath)}` });
                        
                        const deleteResult = await sftp.delete(deleteFilePath);
                        msg.payload = deleteResult;
                        msg.deletedPath = deleteFilePath;
                        
                        node.status({ fill: 'green', shape: 'dot', text: 'file deleted' });
                        send(msg);
                        break;
                    }

                    /**
                     * MKDIR OPERATION
                     * Creates a directory on the SFTP server
                     * Input: msg.payload (optional) - path of directory to create
                     * Output: msg.payload - mkdir result
                     */
                    case 'mkdir': {
                        const mkdirPath = PathUtils.normalizeRemote(
                            msg.payload && typeof msg.payload === 'string' ? msg.payload : msgConfig.workdir
                        );
                        
                        if (!mkdirPath || mkdirPath === './') {
                            throw new Error('Invalid directory path for mkdir operation');
                        }
                        
                        node.status({ fill: 'blue', shape: 'dot', text: `creating ${mkdirPath}` });
                        
                        // Second parameter: recursive (false = fail if parent doesn't exist)
                        const mkdirResult = await sftp.mkdir(mkdirPath, false);
                        msg.payload = mkdirResult;
                        msg.createdPath = mkdirPath;
                        
                        node.status({ fill: 'green', shape: 'dot', text: 'directory created' });
                        send(msg);
                        break;
                    }

                    /**
                     * RMDIR OPERATION
                     * Removes a directory and its contents from the SFTP server
                     * Input: msg.payload (optional) - path of directory to remove
                     * Output: msg.payload - rmdir result
                     * WARNING: This removes the directory and ALL contents recursively
                     */
                    case 'rmdir': {
                        const rmdirPath = PathUtils.normalizeRemote(
                            msg.payload && typeof msg.payload === 'string' ? msg.payload : msgConfig.workdir
                        );
                        
                        if (!rmdirPath || rmdirPath === './' || rmdirPath === '/' || rmdirPath === '.') {
                            throw new Error('Invalid or dangerous directory path for rmdir operation');
                        }
                        
                        node.status({ fill: 'blue', shape: 'dot', text: `removing ${rmdirPath}` });
                        
                        // FIX: Original code incorrectly called mkdir instead of rmdir
                        // Using rmdir with recursive=true to remove directory and contents
                        const rmdirResult = await sftp.rmdir(rmdirPath, true);
                        msg.payload = rmdirResult;
                        msg.removedPath = rmdirPath;
                        
                        node.status({ fill: 'green', shape: 'dot', text: 'directory removed' });
                        send(msg);
                        break;
                    }

                    default:
                        throw new Error(`Invalid operation: ${msgConfig.operation}`);
                }

                // Operation completed successfully
                node.status({ fill: 'gray', shape: 'ring', text: 'done' });
                done();

            } catch (err) {
                // Handle any errors that occurred during the operation
                const errorMessage = err.message || String(err);
                node.status({ fill: 'red', shape: 'ring', text: errorMessage.substring(0, 30) });
                createErrorMessage(err, msg, conSettings);
                done(err);
                
            } finally {
                // Always close the connection
                await safeClose(sftp, connectionState);
                
                // Clear status after a short delay
                setTimeout(() => {
                    node.status({});
                }, 3000);
            }
        });

        /**
         * Node close handler
         * Called when the node is stopped or deleted
         */
        node.on('close', function (done) {
            node.status({});
            done();
        });
    }

    // Register the operation node type
    RED.nodes.registerType('sftp in', SFtpInNode);
};
