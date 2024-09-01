#!/usr/bin/env python
#
# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#

import logging
logging.basicConfig(encoding="utf-8", level=logging.INFO)
from siem_mtad_gat.ad_opensearch_extension.ad_opensearch_extension import ADOpenSearchExtension
from opensearch_sdk_py.server.async_extension_host import AsyncExtensionHost


extension = ADOpenSearchExtension()
logging.info(f"Starting {extension} that implements {extension.implemented_interfaces}.")

host = AsyncExtensionHost(address="localhost", port=1234)
host.serve(extension)

logging.info(f"Listening on {host.address}:{host.port}.")
host.run()
