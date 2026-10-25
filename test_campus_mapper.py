import unittest
from unittest.mock import patch

import campus_mapper as m


class MapperTests(unittest.TestCase):
    def test_nginx_map_keeps_domain_and_port_but_not_internal_target(self):
        config = """server {
          listen 443 ssl;
          server_name example.edu www.example.edu;
          location /library/ {
            proxy_pass http://127.0.0.1:18081;
          }
          proxy_set_header Authorization secret-value;
        }
        """
        rows = m.parse_nginx_text(config, "site.conf")
        self.assertEqual(rows[0]["names"], ["example.edu", "www.example.edu"])
        self.assertEqual(rows[0]["listen"], [443])
        self.assertEqual(rows[0]["routes"][0], {
            "path": "/library/", "kind": "proxy_pass", "scope": "loopback",
            "port": 18081, "target_host": "127.0.0.1", "socket_id": None})
        self.assertNotIn("secret-value", str(rows))
        report = {"host": "web1", "collected_at": "now", "services": [], "containers": [],
                  "listeners": [{"port": 18081, "bind": "loopback", "process": "php"}],
                  "nginx_vhosts": rows, "apache_vhosts": [], "nginx_upstreams": {},
                  "local_addresses": ["127.0.0.1"], "warnings": [], "backup_indicators": []}
        summary = m.markdown([report])
        self.assertNotIn("127.0.0.1", summary)
        self.assertIn("web1:18081", summary)
        plain = m.plain_text([report])
        self.assertIn("ПУБЛИЧНЫЕ ИМЕНА", plain)
        self.assertNotIn("|---", plain)
        self.assertNotIn("##", plain)
        self.assertNotIn("Сервер: ---", plain)
        cards = m.service_cards([report])
        self.assertIn("1. example.edu", cards)
        self.assertIn("Решение о включении: НЕ ПРИНЯТО", cards)
        self.assertNotIn("127.0.0.1", cards)
        both = dict(report, nginx_vhosts=rows + [{"names": ["example.edu"], "listen": [80], "routes": []}])
        grouped_cards = m.service_cards([both])
        self.assertEqual(grouped_cards.count("1. example.edu"), 1)
        self.assertIn("80, 443", grouped_cards)

    def test_listener_does_not_export_ip_or_pid(self):
        rows = m.parse_listeners('LISTEN 0 511 192.0.2.44:443 0.0.0.0:* users:(("nginx",pid=42,fd=7))')
        self.assertEqual(rows, [{"port": 443, "bind": "specific_interface", "process": "nginx"}])
        self.assertNotIn("192.0.2.44", str(rows))
        self.assertNotIn("42", str(rows))

    def test_invalid_hostnames_are_not_exported(self):
        rows = m.parse_nginx_text('server {\nserver_name safe.example $(secret);\n}', 'site.conf')
        self.assertEqual(rows[0]["names"], ["safe.example"])

    def test_cross_host_link_from_private_inventory(self):
        source = {"host": "edge", "nginx_upstreams": {}, "local_addresses": [],
                  "listeners": [], "containers": []}
        backend = {"host": "app", "nginx_upstreams": {}, "local_addresses": ["192.0.2.3"],
                   "listeners": [{"port": 9000}], "containers": []}
        route = m.host_port("http://192.0.2.3:9000/")
        self.assertEqual(m.resolve_target(source, route, [source, backend]),
                         "app:9000 (слушатель наблюдался; работа сервиса не проверена)")

    def test_upstream_pool_is_explicitly_unresolved(self):
        source = {"host": "edge", "nginx_upstreams": {"apps": [
            m.host_port("192.0.2.3:9000"), m.host_port("192.0.2.4:9000")]}}
        self.assertIn("группа upstream", m.resolve_target(source, m.host_port("http://apps/"), [source]))

    def test_cyclic_upstream_config_is_reported_without_recursion(self):
        source = {"host": "edge", "nginx_upstreams": {
            "first": [m.host_port("http://second/")],
            "second": [m.host_port("http://first/")]}}
        self.assertIn("циклическая", m.resolve_target(source, m.host_port("http://first/"), [source]))

    def test_php_socket_link_without_disclosing_path(self):
        target = m.host_port("unix:/run/php/php8.5-fpm.sock")
        source = {"host": "web", "php_pools": [{"pool": "www", "listen": target}]}
        self.assertIn("пул PHP-FPM www", m.resolve_target(source, target, [source]))
        self.assertNotIn("/run/php", m.resolve_target(source, target, [source]))

    def test_reverse_tunnel_links_ingress_to_other_host(self):
        edge = {"host": "edge", "local_addresses": [], "nginx_upstreams": {},
                "listeners": [{"port": 18080}], "containers": []}
        app = {"host": "app", "local_addresses": [], "nginx_upstreams": {},
               "listeners": [{"port": 8080}], "containers": [], "tunnels": [{
                   "direction": "R", "active": True, "listen_port": 18080,
                   "target_port": 8080}]}
        result = m.resolve_target(edge, m.host_port("http://127.0.0.1:18080"), [edge, app])
        self.assertIn("app:8080", result)
        self.assertIn("обратного туннеля", result)

    def test_backend_without_vhost_gets_tunnel_card(self):
        report = {"host": "app", "nginx_vhosts": [], "apache_vhosts": [],
                  "listeners": [{"port": 8080}], "containers": [],
                  "tunnels": [{"direction": "R", "target_port": 8080,
                               "unit": "app-tunnel.service", "active": True}]}
        cards = m.service_cards([report])
        self.assertIn("ВНУТРЕННИЙ СЕРВИС 1 — локальный порт 8080", cards)
        self.assertIn("Публичный адрес: НЕ УСТАНОВЛЕН", cards)
        self.assertIn("Локальный слушатель: наблюдался", cards)

    def test_pool_branch_does_not_invent_patch_version(self):
        report = {"php_pools": [{"pool": "web", "php_version_from_config_path": "8.5"}],
                  "versions_cli_only": {}, "listeners": []}
        findings = m.security_findings(report)
        self.assertFalse(any(x["priority"] == "критический" for x in findings))
        self.assertTrue(any("полную версию" in x["verify_before_enable"] for x in findings))

    def test_old_php_cli_is_candidate_not_confirmed_web_runtime(self):
        report = {"php_pools": [], "versions_cli_only": {"php_cli": "PHP 8.5.11 (cli)"},
                  "listeners": []}
        findings = m.security_findings(report)
        self.assertTrue(any(x["priority"] == "критический" for x in findings))
        self.assertTrue(any("версию работающего PHP" in x["verify_before_enable"] for x in findings))

    def test_php_cli_branch_without_patch_does_not_claim_critical_release_gap(self):
        report = {"php_pools": [], "versions_cli_only": {"php_cli": "PHP 8.5 (cli)"},
                  "listeners": []}
        findings = m.security_findings(report)
        self.assertFalse(any(x["priority"] == "критический" for x in findings))
        self.assertTrue(any("полную версию" in x["verify_before_enable"] for x in findings))

    def test_nginx_development_branch_is_checked_against_its_own_fix(self):
        report = {"php_pools": [], "versions_cli_only": {"nginx": "nginx version: nginx/1.31.6"},
                  "listeners": []}
        self.assertTrue(any("nginx CLI" in x["observed"] for x in m.security_findings(report)))
        report["versions_cli_only"]["nginx"] = "nginx version: nginx/1.31.7"
        self.assertFalse(any("nginx CLI" in x["observed"] for x in m.security_findings(report)))

    def test_apache_october_release_is_review_candidate(self):
        report = {"php_pools": [], "versions_cli_only": {"apache2": "Server version: Apache/2.4.68"},
                  "listeners": []}
        self.assertTrue(any("Apache HTTP Server" in x["observed"] for x in m.security_findings(report)))
        report["versions_cli_only"]["apache2"] = "Server version: Apache/2.4.69"
        self.assertFalse(any("Apache HTTP Server" in x["observed"] for x in m.security_findings(report)))

    def test_database_listener_is_risk_only(self):
        report = {"php_pools": [], "versions_cli_only": {},
                  "listeners": [{"port": 3306, "bind": "all_interfaces"}]}
        findings = m.security_findings(report)
        self.assertEqual(findings[0]["priority"], "высокий")
        self.assertIn("firewall/NAT неизвестны", findings[0]["possible_risk"])

    def test_unmapped_listener_is_marked_for_owner_review(self):
        report = {"php_pools": [], "versions_cli_only": {},
                  "listeners": [{"port": 8443, "bind": "all_interfaces"}],
                  "nginx_vhosts": [], "apache_vhosts": []}
        findings = m.security_findings(report)
        self.assertTrue(any("явной связи" in x["observed"] for x in findings))

    def test_stopped_legacy_php_image_is_flagged_as_image_evidence(self):
        report = {"php_pools": [], "versions_cli_only": {}, "listeners": [],
                  "containers": [{"name": "old-site", "image_tag": "php:5.6", "state": "exited"}]}
        findings = m.security_findings(report)
        self.assertTrue(any("метка образа" in x["observed"] and "не поддерживается" in x["possible_risk"]
                            for x in findings))

    def test_package_inventory_keeps_full_list_private_and_selects_runtime(self):
        sample = "nginx\t1.28.0-1ubuntu1\nlibexample\t4.0\n"
        with patch.object(m.shutil, "which", return_value="/usr/bin/dpkg-query"), \
             patch.object(m, "run", return_value=(sample, None)):
            packages = m.package_versions([])
        self.assertEqual(len(packages["all"]), 2)
        self.assertEqual([x["package"] for x in packages["selected"]], ["nginx"])

    def test_certificate_wildcard_matches_one_label_only(self):
        self.assertTrue(m.cert_name_match("portal.example.edu", ["*.example.edu"]))
        self.assertFalse(m.cert_name_match("a.portal.example.edu", ["*.example.edu"]))

    def test_certificate_inventory_does_not_keep_subject(self):
        sample = "notBefore=Oct 01 00:00:00 2026 GMT\nnotAfter=Jan 01 00:00:00 2027 GMT\nsubject=CN=Person Name\nDNS:example.edu\n"
        with patch.object(m.Path, "is_file", return_value=True), \
             patch.object(m, "run", return_value=(sample, None)) as call:
            rows = m.certificate_inventory(["/tmp/example.crt"])
        self.assertNotIn("-subject", call.call_args.args[0])
        self.assertNotIn("Person Name", str(rows))
        self.assertEqual(rows[0]["names"], ["example.edu"])

    def test_php_signal_requires_effective_web_value_check(self):
        report = {"php_pools": [], "versions_cli_only": {}, "listeners": [],
                  "php_setting_signals": [{"php_branch": "8.5", "config_kind": "pool",
                                           "configured": "on"}]}
        findings = m.security_findings(report)
        self.assertTrue(any("действующее значение" in x["verify_before_enable"] for x in findings))

    def test_docker_inventory_includes_stopped_containers(self):
        listing = '{"ID":"' + "a" * 64 + '","Names":"legacy","Image":"php:5.6","State":"exited","Ports":""}'
        with patch.object(m, "run", side_effect=[(listing, None), (None, "unavailable")]) as call:
            rows = m.docker_inventory([])
        self.assertIn("--all", call.call_args_list[0].args[0])
        self.assertIn("unix:///var/run/docker.sock", call.call_args_list[0].args[0])
        self.assertEqual(rows[0]["state"], "exited")

    def test_stale_health_of_exited_container_is_not_active_alert(self):
        report = {"host": "app", "nginx_vhosts": [], "apache_vhosts": [],
                  "listeners": [], "services": [], "containers": [{"name": "old", "state": "exited",
                  "health": "unhealthy", "restarts": 0, "image_tag": "php:5.6",
                  "published_ports": []}], "backup_indicators": [{"name": "backup.service"}]}
        attention = m.markdown([report]).split("## Требует внимания", 1)[1]
        self.assertNotIn("контейнер old", attention)

    def test_disabled_unit_files_remain_visible(self):
        with patch.object(m, "run", side_effect=[("campus-app.service disabled enabled\n", None),
                                                 (None, "unavailable")]):
            rows = m.service_unit_files([])
        self.assertEqual(rows[0]["unit_file_state"], "disabled")

    def test_nginx_location_does_not_bleed_into_next_route(self):
        rows = m.parse_nginx_text("""server {
          server_name example.edu;
          location /a/ { proxy_pass http://127.0.0.1:8080;
          }
          location /b/ {
          proxy_pass http://127.0.0.1:8081;
          }
        }""", "site.conf")
        self.assertEqual(rows[0]["routes"][0]["path"], "/b/")

    def test_php_setting_collects_only_allowlisted_value(self):
        config = "secret = EXAMPLE_VALUE\nsession.upload_progress.enabled = 0\n"
        with patch.object(m.glob, "glob", side_effect=[
            ["/etc/php/8.5/fpm/php.ini"], [], []]), patch.object(m, "read_config", return_value=config):
            signals = m.php_setting_signals([])
        self.assertEqual(signals[0]["configured"], "off")
        self.assertNotIn("EXAMPLE_VALUE", str(signals))

    def test_deleted_listener_binary_is_review_candidate(self):
        raw = 'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("php-fpm",pid=123,fd=4))'
        with patch.object(m.os, "readlink", return_value="/usr/sbin/php-fpm (deleted)"):
            rows = m.listener_processes(raw)
        self.assertEqual(rows[0]["executable"], "php-fpm")
        self.assertTrue(rows[0]["deleted_executable"])
        self.assertNotIn("127.0.0.1", str(rows))

    def test_collect_wires_security_and_journal_without_raw_messages(self):
        with patch.object(m, "run", return_value=("", None)), \
             patch.object(m, "nginx_inventory", return_value=([], {}, [])), \
             patch.object(m, "apache_inventory", return_value=([], [])), \
             patch.object(m, "services", return_value=[]), \
             patch.object(m, "service_unit_files", return_value=[]), \
             patch.object(m, "docker_inventory", return_value=[]), \
             patch.object(m, "journal_error_summary", return_value=({"system:web.service": 1},
                                                                       {"system:web.service": {"нет места на диске": 1}})), \
             patch.object(m, "software_versions", return_value={"php_cli": "PHP 8.5.11 (cli)"}), \
             patch.object(m, "package_versions", return_value={"manager": "dpkg", "all": [], "selected": []}), \
             patch.object(m, "php_pool_inventory", return_value=[]), \
             patch.object(m, "php_setting_signals", return_value=[]), \
             patch.object(m, "certificate_inventory", return_value=[]), \
             patch.object(m, "backup_indicators", return_value=[]), \
             patch.object(m, "tunnel_inventory", return_value=[]), \
             patch.object(m, "local_addresses", return_value=[]), \
             patch.object(m, "disk_root", return_value="10%"), \
             patch.object(m, "distribution", return_value={"id": "ubuntu"}):
            report = m.collect()
        self.assertTrue(any(x["priority"] == "критический" for x in report["security_triage"]))
        self.assertEqual(report["journal_categories_24h"]["system:web.service"]["нет места на диске"], 1)
        self.assertNotIn("MESSAGE", str(report))

    def test_public_reports_show_felix_fons_contact(self):
        report = {"host": "example-host", "nginx_vhosts": [], "apache_vhosts": [],
                  "listeners": [], "services": [], "containers": [], "warnings": []}
        self.assertIn("https://felixfons.ru", m.plain_text([report]))
        self.assertIn("FELIX FONS", m.service_cards([report]))



if __name__ == "__main__":
    unittest.main()
