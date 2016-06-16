package easysftp

import (
	"errors"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

// resumeBufferSize is the size of writes when downloading via sftp (32KiB) * 2
const resumeBufferSize = 1 << 16

// ClientConfig maintains all of the configuration info to connect to a SSH host
type ClientConfig struct {
	Username string
	Host     string
	KeyPath  string
	Password string
	Timeout  time.Duration
	FileMode os.FileMode
}

// Client communicates with the SFTP to download files/pathes
type Client struct {
	sshClient *ssh.Client
	config    *ClientConfig
}

// Connect to a host with this given config
func Connect(config *ClientConfig) (*Client, error) {
	var auth []ssh.AuthMethod
	if config.KeyPath != "" {
		privKey, err := ioutil.ReadFile(config.KeyPath)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(privKey)
		if err != nil {
			return nil, err
		}

		auth = append(auth, ssh.PublicKeys(signer))
	}

	if len(auth) == 0 {
		if config.Password == "" {
			return nil, errors.New("Missing password or key for SSH authentication")
		}

		auth = append(auth, ssh.Password(config.Password))
	}

	sshClient, err := ssh.Dial("tcp", config.Host, &ssh.ClientConfig{
		User:    config.Username,
		Auth:    auth,
		Timeout: config.Timeout,
	})
	if err != nil {
		return nil, err
	}

	return &Client{
		sshClient: sshClient,
		config:    config,
	}, nil
}

// Close the underlying SSH conection
func (c *Client) Close() error {
	return c.sshClient.Close()
}

func (c *Client) newSftpClient() (*sftp.Client, error) {
	return sftp.NewClient(c.sshClient)
}

// Stat gets information for the given path
func (c *Client) Stat(path string) (os.FileInfo, error) {
	sftpClient, err := c.newSftpClient()
	if err != nil {
		return nil, err
	}

	defer sftpClient.Close()

	return sftpClient.Stat(path)
}

// Lstat gets information for the given path, if it is a symbolic link, it will describe the symbolic link
func (c *Client) Lstat(path string) (os.FileInfo, error) {
	sftpClient, err := c.newSftpClient()
	if err != nil {
		return nil, err
	}

	defer sftpClient.Close()

	return sftpClient.Lstat(path)
}

// Download a file from the given path to the output writer with the given offset of the remote file
func (c *Client) Download(path string, output io.Writer, offset int64) error {
	sftpClient, err := c.newSftpClient()
	if err != nil {
		return err
	}

	defer sftpClient.Close()

	info, err := sftpClient.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return errors.New("Unable to use easysftp.Client.Download for dir: " + path)
	}

	remote, err := sftpClient.Open(path)
	if err != nil {
		return err
	}

	defer remote.Close()

	_, err = remote.Seek(offset, 0)
	if err != nil {
		return err
	}

	_, err = io.Copy(output, remote)
	return err
}

// Mirror downloads an entire folder (recursively) or file underneath the given localParentPath
// resume will try to continue downloading interrupted files
func (c *Client) Mirror(path string, localParentPath string, resume bool) error {
	sftpClient, err := c.newSftpClient()
	if err != nil {
		return err
	}

	defer sftpClient.Close()

	info, err := sftpClient.Stat(path)
	if err != nil {
		return err
	}

	// download the file
	if !info.IsDir() {
		sftpClient.Close()
		localPath := filepath.Join(localParentPath, info.Name())
		localInfo, err := os.Stat(localPath)
		if os.IsExist(err) && localInfo.IsDir() {
			err = os.RemoveAll(localPath)
			if err != nil {
				return err
			}
		}

		flags := os.O_RDWR | os.O_CREATE

		if !resume {
			// truncate the file
			flags |= os.O_TRUNC
		}

		file, err := os.OpenFile(
			localPath,
			flags,
			c.config.FileMode,
		)
		if err != nil {
			return err
		}

		defer file.Close()

		var offset int64
		if resume {
			info, err := file.Stat()
			if err != nil {
				return err
			}

			offset = info.Size() - resumeBufferSize
			if offset <= 0 {
				offset = 0
			} else {
				_, err = file.Seek(offset, 0)
				if err != nil {
					return err
				}

				buf := make([]byte, resumeBufferSize)
				_, err = file.Read(buf)
				if err != nil {
					return err
				}

				for _, val := range buf {
					if val == 0 {
						break
					}

					offset++
				}

				_, err = file.Seek(offset, 0)
				if err != nil {
					return err
				}
			}
		}

		return c.Download(path, file, offset)
	}

	// download the whole directory recursively
	walker := sftpClient.Walk(path)
	remoteParentPath := filepath.Dir(path)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			return err
		}

		info := walker.Stat()

		relPath, err := filepath.Rel(remoteParentPath, walker.Path())
		if err != nil {
			return err
		}

		localPath := filepath.Join(localParentPath, relPath)

		// if we have something at the download path delete it if it is a directory
		// and the remote is a file and vice a versa
		localInfo, err := os.Stat(localPath)
		if os.IsExist(err) {
			if localInfo.IsDir() {
				if info.IsDir() {
					continue
				}

				err = os.RemoveAll(localPath)
				if err != nil {
					return err
				}
			} else if info.IsDir() {
				err = os.Remove(localPath)
				if err != nil {
					return err
				}
			}
		}

		if info.IsDir() {
			err = os.MkdirAll(localPath, c.config.FileMode)
			if err != nil {
				return err
			}

			continue
		}

		remoteFile, err := sftpClient.Open(walker.Path())
		if err != nil {
			return err
		}

		flags := os.O_RDWR | os.O_CREATE

		if !resume {
			flags |= os.O_TRUNC
		}

		localFile, err := os.OpenFile(localPath, flags, c.config.FileMode)
		if err != nil {
			remoteFile.Close()
			return err
		}

		if resume {
			info, err := localFile.Stat()
			if err != nil {
				return err
			}

			offset := info.Size() - resumeBufferSize
			if offset <= 0 {
				offset = 0
			} else {
				_, err = localFile.Seek(offset, 0)
				if err != nil {
					return err
				}

				buf := make([]byte, resumeBufferSize)
				_, err = localFile.Read(buf)
				if err != nil {
					return err
				}

				for _, val := range buf {
					if val == 0 {
						break
					}

					offset++
				}

				_, err = localFile.Seek(offset, 0)
				if err != nil {
					return err
				}
			}

			_, err = remoteFile.Seek(offset, 0)
			if err != nil {
				return err
			}
		}

		_, err = io.Copy(localFile, remoteFile)
		remoteFile.Close()
		localFile.Close()

		if err != nil {
			return err
		}
	}

	return nil
}
