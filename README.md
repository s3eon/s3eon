# S3eon

S3eon is a project that enhances the security and flexibility of S3 interactions. It provides several functions:

1. **SSE-C (Server-Side Encryption with Customer-Provided Keys)**: S3eon increases the security of S3 by implementing SSE-C, allowing users to manage their encryption keys.

1. **URL Style Conversion** : S3eon supports converting between path-style and virtual-hosted-style URLs for S3 access.

1. **Credential Management**: S3eon enables the transformation of a single upstream S3 credential into multiple downstream credentials, allowing secure and controlled access distribution across different systems or environments.

## Usage

To use S3eon, you can either use the provided Docker image or download the binary from the GitHub Release. Here's an example using docker-compose:

1. Configure your S3 credentials and settings in the `docker-compose.yml` file.
2. Run `docker-compose up` to start S3eon.

You can find the Docker image in the GitHub Package repository and the binary in the GitHub Release section.

## Installation

- **Docker**: Pull the image from GitHub Package: `docker pull ghcr.io/s3eon/s3eon:latest`
- **Binary**: Download the latest binary from the [GitHub Release](https://github.com/s3eon/s3eon/releases/latest)

## Contributing

Contributions are welcome. Please submit pull requests to the main branch.

## License

This project is licensed under the AGPL v3 License.
