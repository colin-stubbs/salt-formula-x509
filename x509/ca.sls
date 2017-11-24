{# x509.ca #}

{# NOTE: Generates or installs appropriate keys/certificates for CA minions based on pillar. Assign to CA minion/s ONLY. #}

include:
  - x509

{% from "x509/map.jinja" import x509_settings, x509_issued_cert_defaults, x509_ca_cert_defaults with context %}

{% if grains.kernel == 'Linux' %}

{{ x509_settings.lookup.locations.ca_certs_dir }}:
  file.directory:
    - makedirs: True
    - user: root
    - group: root
    - mode: 0750

{{ x509_settings.lookup.locations.ca_keys_dir }}:
  file.directory:
    - makedirs: True
    - user: root
    - group: root
    - mode: 0750

{{ x509_settings.lookup.locations.issued_crls_dir }}:
  file.directory:
    - makedirs: True
    - user: root
    - group: root
    - mode: 0755

{{ x509_settings.lookup.locations.issued_certs_dir }}:
  file.directory:
    - makedirs: True
    - user: root
    - group: root
    - mode: 0755

{{ x509_settings.lookup.locations.issued_keys_dir }}:
  file.directory:
    - makedirs: True
    - user: root
    - group: root
    - mode: 0755

{% if 'ca' in x509_settings %}
{% if 'static' in x509_settings.ca %}
{% if 'certificates' in x509_settings.ca.static %}
{% for certificate_name, certificate in x509_settings.ca.static.certificates.items()|default({}) %}
{{ x509_settings.lookup.locations.ca_certs_dir }}/{{ certificate_name }}.crt:
  file.managed:
    {% if 'content' in certificate %}
    - pillar_contents: x509:ca:static:certificates:{{ certificate_name }}:content
    {% elif 'source' in certificate %}
    - source: {{ certificate.source }}
    {% endif %}
    - user: {{ certificate.user|default('root') }}
    - group: {{ certificate.group|default('root') }}
    - mode: {{ certificate.mode|default('0644') }}
    - require:
      - file: {{ x509_settings.lookup.locations.ca_certs_dir }}
{% endfor %}
{% endif %}

{% if 'private_keys' in x509_settings.ca.static %}
{% for private_key_name, private_key in x509_settings.ca.static.private_keys.items()|default({}) %}
{{ x509_settings.lookup.locations.ca_keys_dir }}/{{ private_key_name }}.key:
  file.managed:
    {% if 'content' in private_key %}
    - pillar_contents: x509:ca:static:keys:{{ private_key_name }}:content
    {% elif 'source' in private_key %}
    - source: {{ private_key.source }}
    {% endif %}
    - user: {{ private_key.user|default('root') }}
    - group: {{ private_key.group|default('root') }}
    - mode: {{ private_key.mode|default('0640') }}
    - require:
      - file: {{ x509_settings.lookup.locations.ca_keys_dir }}
{% endfor %}
{% endif %}

{% endif %}

{% endif %} {# if x509.ca.static #}

{% if 'signing_policies' in x509_settings.ca %}
{% if 'location' in x509_settings.ca.signing_policies %}
{{ x509_settings.ca.signing_policies.location }}:
{% else %}
/etc/salt/minion.d/signing_policies.conf:
{% endif %}
  file.managed:
    {% if 'content' in x509_settings.ca.signing_policies %}
    - pillar_contents: x509:ca:signing_policies:content
    {% elif 'source' in x509_settings.ca.signing_policies %}
    - source: {{ x509_settings.ca.signing_policies.source }}
    {% endif %}
    - user: {{ x509_settings.ca.signing_policies.user|default('root') }}
    - group: {{ x509_settings.ca.signing_policies.group|default('root') }}
    - mode: {{ x509_settings.ca.signing_policies.mode|default('0640') }}

{# TODO - ensure salt-minion service is restarted after changes to signing policy config file #}

{% endif %} {# if x509.ca.signing_policies #}

{# generate CA's and certificates #}
{% if 'generate' in x509_settings.ca %}

{% for ca1_name, ca1 in x509_settings.ca.generate.items() %}

{% if 'create' in ca1 %}
{% for cert_name, cert in ca1.create.items() %}

{% set signer_name = ca1_name %}

{% set certificate_attributes = salt['pillar.get'](
    'x509:ca:generate:' ~ ca1_name ~ ':create:' ~ cert_name ~ ':attributes',
    default=x509_issued_cert_defaults,
    merge=True
  )
%}

{{ x509_settings.lookup.locations.issued_certs_dir }}/{{ cert_name }}.crt:
  x509.certificate_managed:
    - signing_private_key: {{ x509_settings.lookup.locations.ca_keys_dir }}/{{ signer_name }}.key
    - signing_cert: {{ x509_settings.lookup.locations.ca_certs_dir }}/{{ signer_name }}.crt
    {%- for attribute_name, attribute_value in certificate_attributes.items() %}
    {%- if attribute_value != '' %}
    - {{ attribute_name }}: {{ attribute_value }}
    {%- endif %}
    {%- endfor %}
    - require:
      - file: {{ x509_settings.lookup.locations.issued_certs_dir }}

{# TODO - use mine.send to make CA cert available to minions #}

{% endfor %}
{% endif %} {# create in ca1 #}

{% if 'sub' in ca1 %}
{% for ca2_name, ca2 in ca1.sub.items() %}

{% if 'create' in ca2 %}
{% for cert_name, cert in ca2.create.items() %}
{% endfor %}
{% endif %} {# create in ca2 #}

{% if 'sub' in ca2 %}
{% for ca3_name, ca3 in ca2.sub.items() %}

{% if 'create' in ca3 %}
{% for cert_name, cert in ca3.create.items() %}
{% endfor %}
{% endif %} {# create in ca3 #}

{% endfor %}
{% endif %} {# sub in ca2 #}
{% endfor %}
{% endif %} {# sub in ca1 #}

{% endfor %}

{% endif %} {# x509.ca.generate #}

{% endif %} {# x509.ca #}

{# EOF #}
