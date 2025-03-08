FROM blacktop/ghidra AS ghidra

ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

# We want Ghidra from the base image
COPY --from=ghidra /ghidra /ghidra
ENV GHIDRA_INSTALL_DIR /ghidra

# Python path to the service class from your service directory
ENV SERVICE_PATH ghidra_auto_analysis.ghidra_auto_analysis.GhidraAutoAnalysis

# Install apt dependencies
USER root
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

# Install python dependencies
USER assemblyline
COPY requirements.txt requirements.txt
RUN pip install \
    --no-cache-dir \
    --user \
    --requirement requirements.txt && \
    rm -rf ~/.cache/pip

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=1.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
