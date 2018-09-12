
EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure url to be filtered by fortigate
    fortios_webfilter:
      host:  "{{  host }}"
      username: "{{  username}}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      webfilter_url:
        state: "present"
        id: "1"
        name: "default"
        comment: "mycomment"
        one-arm-ips-url-filter: "disable"
        ip-addr-block: "disable"
        entries:
          - id: "1"
            url: "www.test1.com"
            type: "simple"
            action: "exempt"
            status: "enable"
            exempt: "pass"
            web-proxy-profile: ""
            referrrer-host: ""
          - id: "2"
            url: "www.test2.com"
            type: "simple"
            action: "exempt"
            status: "enable"
            exempt: "pass"
            web-proxy-profile: ""
            referrrer-host: ""


- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure web content filtering in fortigate
    fortios_webfilter:
      host:  "{{  host }}"
      username: "{{  username}}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      webfilter_content:
        id: "1"
        name: "default"
        comment: ""
        entries:
          - name: "1"
            pattern-type: "www.test45.com"
            status: "enable"
            lang: "western"
            score: 40
            action: "block"
          - name: "2"
            pattern-type: "www.test46.com"
            status: "enable"
            lang: "western"
            score: 42
            action: "block"
        state: "present"
'''
