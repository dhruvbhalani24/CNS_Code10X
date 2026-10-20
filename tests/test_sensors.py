from sensors.traffic_simulator import TrafficSimulator
from sensors.zeek_sensor import ZeekSensor


def test_zeek_sensor_reads_tsv_log(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\tservice\t"
        "duration\torig_bytes\tresp_bytes\tconn_state\n"
        "1700000000.0\t10.0.1.2\t10.0.0.10\t443\ttcp\tssl\t0.5\t"
        "1200\t3400\tSF\n",
        encoding="utf-8",
    )

    events = list(ZeekSensor(str(tmp_path), tail=False).stream())

    assert len(events) == 1
    assert events[0].src_ip == "10.0.1.2"
    assert events[0].dst_port == 443
    assert events[0].sensor == "zeek"


def test_simulator_zeek_logs_round_trip(tmp_path):
    simulator = TrafficSimulator(seed=7, normal_events=3, attacks=["port_scan"])
    expected = simulator.build()
    log_dir = simulator.write_zeek_logs(str(tmp_path))

    events = list(ZeekSensor(str(log_dir), tail=False).stream())

    assert len(events) == len(expected)
    assert events[0].src_ip == expected[0].src_ip
    assert events[0].dst_port == expected[0].dst_port
