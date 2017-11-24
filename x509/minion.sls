{# x509.minion #}

{# NOTE: Generates appropriate keys/certificates for minions based on pillar. Assign to minion/s. #}

include:
  - x509

{% from "x509/map.jinja" import x509_settings with context %}
