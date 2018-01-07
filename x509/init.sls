{# x509 #}

{# NOTE: Sets up dependencies for all minion types, e.g. CA minions and non-CA minions. #}

{% from "x509/map.jinja" import x509_settings, x509_issued_cert_defaults, x509_ca_cert_defaults with context %}

{{ x509_settings.lookup.locations.certs_dir }}:
  file.directory:
    - makedirs: True
    {% if grains.kernel == 'Windows' %}
    - win_owner: Administrator
    - win_perms: {'Administrators': {'perms': 'full_control'}}
    - win_inheritance: False
    {% elif grains.kernel == 'Darwin' %}
    - user: root
    - group: wheel
    - mode: 0755
    {% else %}
    - user: root
    - group: root
    - mode: 0755
    {% endif %}

{{ x509_settings.lookup.locations.keys_dir }}:
  file.directory:
    - makedirs: True
    {% if grains.kernel == 'Windows' %}
    - win_owner: Administrator
    - win_perms: {'Administrators': {'perms': 'full_control'}}
    - win_inheritance: False
    {% elif grains.kernel == 'Darwin' %}
    - user: root
    - group: wheel
    - mode: 0755
    {% else %}
    - user: root
    - group: root
    - mode: 0755
    {% endif %}

{{ x509_settings.lookup.locations.trust_anchors_dir }}:
  file.directory:
    - makedirs: True
    {% if grains.kernel == 'Windows' %}
    - win_owner: Administrator
    - win_perms: {'Administrators': {'perms': 'full_control'}}
    - win_inheritance: False
    {% elif grains.kernel == 'Darwin' %}
    - user: root
    - group: wheel
    - mode: 0755
    {% else %}
    - user: root
    - group: root
    - mode: 0755
    {% endif %}

{# Do what's necessary on Linux systems #}
{% if grains.kernel == 'Linux' %}
x509-pkgs:
  pkg.installed:
    - pkgs: {{ x509_settings.lookup.pkgs }}
{% endif %}

{# Install static certificates based on pillar #}
{% if 'minion' in x509_settings %}
{% if 'static' in x509_settings.minion %}
{% if 'certificates' in x509_settings.minion.static %}
{% for certificate_name, certificate in x509_settings.minion.static.certificates.items()|default({}) %}
{% if 'location' in certificate %}
{{ certificate.location }}:
{% else %}
{{ x509_settings.lookup.locations.certs_dir }}/{{ certificate_name }}.crt:
{% endif %}
  file.managed:
    {% if 'content' in certificate %}
    - contents_pillar: x509:minion:static:certificates:{{ certificate_name }}:content
    {% elif 'source' in certificate %}
    - source: {{ certificate.source }}
    {% endif %}
    {% if grains.kernel == 'Windows' %}
    {% elif grains.kernel == 'Linux' or grains.kernel == 'Darwin' %}
    - user: {{ certificate.user|default('root') }}
    {% if grains.kernel == 'Darwin' %}
    - group: {{ certificate.group|default('wheel') }}
    {% else %}
    - group: {{ certificate.group|default('root') }}
    {% endif %}
    - mode: {{ certificate.mode|default('0644') }}
    {% endif %}
    - require:
      - file: {{ x509_settings.lookup.locations.certs_dir }}
{% endfor %}
{% endif %}

{# Install static keys based on pillar #}
{% if 'private_keys' in x509_settings.minion.static %}
{% for private_key_name, private_key in x509_settings.minion.static.private_keys.items()|default({}) %}
{% if 'location' in private_key %}
{{ private_key.location }}:
{% else %}
{{ x509_settings.lookup.locations.keys_dir }}/{{ private_key_name }}.key:
{% endif %}
  file.managed:
    {% if 'content' in private_key %}
    - contents_pillar: x509:minion:static:private_keys:{{ private_key_name }}:content
    {% elif 'source' in private_key %}
    - source: {{ private_key.source }}
    {% endif %}
    {% if grains.kernel == 'Windows' %}
    {% else %}
    - user: {{ private_key.user|default('root') }}
    {% if grains.kernel == 'Darwin' %}
    - group: {{ private_key.group|default('wheel') }}
    {% else %}
    - group: {{ private_key.group|default('root') }}
    {% endif %}
    - mode: {{ private_key.mode|default('0644') }}
    {% endif %}
    - require:
      - file: {{ x509_settings.lookup.locations.keys_dir }}
{% endfor %}
{% endif %}

{# Install static trust anchors based on pillar #}
{% if 'trust_anchors' in x509_settings.minion.static %}
{% for anchor_name, anchor in x509_settings.minion.static.trust_anchors.items()|default({}) %}
{% if 'location' in anchor %}
{{ anchor.location }}:
{% else %}
{{ x509_settings.lookup.locations.trust_anchors_dir }}/{{ anchor_name }}.crt:
{% endif %}
  file.managed:
    {% if 'content' in anchor %}
    - contents_pillar: x509:minion:static:trust_anchors:{{ anchor_name }}:content
    {% elif 'source' in anchor %}
    - source: {{ anchor.source }}
    {% endif %}
    {% if grains.kernel == 'Windows' %}
    {% else %}
    - user: {{ anchor.user|default('root') }}
    {% if grains.kernel == 'Darwin' %}
    - group: {{ anchor.group|default('wheel') }}
    {% else %}
    - group: {{ anchor.group|default('root') }}
    {% endif %}
    - mode: {{ anchor.mode|default('0644') }}
    {% endif %}
    - require:
      - file: {{ x509_settings.lookup.locations.trust_anchors_dir }}

{% if grains.os == 'MacOS' %}

{# TODO: Use 'mac_keychain' state to install certs ? #}

{% elif grains.os == 'Windows' %}

{# TODO: Use 'win_certutil' or 'win_pki' states to install certs ? #}

{% set anchor_store = anchor.store|default('root') %}
{% if anchor_store == 'root' %}
{% set anchor_store_name = 'Root' %}
{% elif anchor_store == 'intermediate' %}
{% set anchor_store_name = 'CA' %}
{% endif %}

{% if 'location' in anchor %}
install-{{ anchor.location }}:
{% else %}
install-{{ x509_settings.lookup.locations.trust_anchors_dir }}/{{ anchor_name }}.crt:
{% endif %}
  win_pki.import_cert:
  {% if 'location' in anchor %}
    - name: install-{{ anchor.location }}
  {% else %}
    - name: {{ x509_settings.lookup.locations.trust_anchors_dir }}/{{ anchor_name }}.crt
  {% endif %}
    - cert_format: 'cer'
    - store: '{{ anchor_store_name }}'

{% endif %}

{% endfor %}

{% if grains.kernel == 'Linux' %}
{# Update trust anchors for use by O/S #}

{% if x509_settings.lookup.update_trust_anchors_cmd != '' %}
trust_anchor_update:
  cmd.run:
    - name: {{ x509_settings.lookup.update_trust_anchors_cmd }}
    - onchanges:
{% for anchor_name, anchor_content in x509_settings.minion.static.trust_anchors.items()|default({}) %}
      - file: {{ x509_settings.lookup.locations.trust_anchors_dir }}/{{ anchor_name }}.crt
{% endfor %}
{% endif %}
{% endif %} {# Linux #}
{% endif %} {# trust anchors #}

{# Install/create chains based on pillar #}
{% if 'chains' in x509_settings.minion.static %}
{% for chain_name, chain in x509_settings.minion.static.chains.items()|default({}) %}
{% if 'content' in chain %}
{% if 'location' in chain %}
{{ chain.location }}:
{% else %}
{{ x509_settings.lookup.locations.certs_dir }}/{{ chain_name }}.crt:
{% endif %}
  file.managed:
    - contents_pillar: x509:minion:static:chains:{{ chain_name }}:content
    {% if grains.kernel == 'Windows' %}
    {% else %}
    - user: {{ chain.user|default('root') }}
    {% if grains.kernel == 'Darwin' %}
    - group: {{ chain.group|default('wheel') }}
    {% else %}
    - group: {{ chain.group|default('root') }}
    {% endif %}
    - mode: {{ chain.mode|default('0644') }}
    {% endif %}
    - require:
      - file: {{ x509_settings.lookup.locations.trust_anchors_dir }}
{% elif 'files' in chain %}

{# TODO - run cat command to concatenate multiple files to single chain file #}

{% endif %}
{% endfor %}
{% endif %} {# chains #}
{% endif %} {# minion #}

{# Generate certificates for the minion based on pillar #}

{% if grains.kernel == 'Linux' and 'generate' in x509_settings.minion %}

{% for cert_name, cert in x509_settings.minion.generate.items()|default({}) %}

{% set certificate_attributes = salt['pillar.get'](
    'x509:minion:generate:' ~ cert_name ~ ':attributes',
    default=x509_issued_cert_defaults,
    merge=True
  )
%}

{% if cert.create_key|default(False) == True %}
{% if 'key_location' in cert %}
{{ cert.key_location }}:
{% else %}
{{ x509_settings.lookup.locations.keys_dir }}/{{ cert_name }}.key:
{% endif %}
  x509.private_key_managed:
    - bits: {{ cert.bits|default(4096) }}
    - backup: {{ cert.backup|default(True) }}
    - require:
      - file: {{ x509_settings.lookup.locations.keys_dir }}
{% endif %}

{% if 'location' in cert %}
{{ cert.location }}:
{% else %}
{{ x509_settings.lookup.locations.certs_dir }}/{{ cert_name }}.crt:
{% endif %}
  x509.certificate_managed:
    {% if cert.create_key|default(False) == True %}
    - public_key: {{ x509_settings.lookup.locations.keys_dir }}/{{ cert_name }}.key
    {% endif %}
    {% if not 'signing_private_key' in certificate_attributes %}
    {# self sign #}
    - signing_private_key: {{ x509_settings.lookup.locations.keys_dir }}/{{ cert_name }}.key
    {% endif %}
    {% for attribute_name, attribute_value in certificate_attributes.items()|default({}) %}
    {% if attribute_value != '' %}
    - {{ attribute_name }}: {{ attribute_value }}
    {% endif %}
    {% endfor %}
    - require:
      - file: {{ x509_settings.lookup.locations.certs_dir }}

{% endfor %} {# for cert_name, cert in x509_settings.minion.generate.items()|default({}) #}

{% endif %} {# if 'generate' in x509_settings.minion #}

{% endif %} {# 'minion' in x509_settings #}

{# EOF #}
