FROM ubuntu:latest

COPY ./dfx.json .
COPY ./run_canisters.sh .


# install dfx
ENV DFX_VERSION=0.10.1
RUN yes | sh -ci "$(curl -fsSL https://sdk.dfinity.org/install.sh)"
ENTRYPOINT ./run_canisters.sh