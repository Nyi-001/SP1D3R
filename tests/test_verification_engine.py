from core.verification_engine import VerificationEngine


def test_file_disclosure_requires_a_known_marker() -> None:
    result = VerificationEngine().verify_file_disclosure(
        'root:x:0:0:root:/root:/bin/bash', ('root:x:0:0:',)
    )
    assert result['state'] == 'confirmed'
    assert result['confidence'] == 'high'
    assert result['matched_marker'] == 'root:x:0:0:'


def test_generic_localhost_text_is_not_file_disclosure_evidence() -> None:
    result = VerificationEngine().verify_file_disclosure(
        '<p>Service URL: http://127.0.0.1:8080</p>',
        ('127.0.0.1', '[extensions]'),
    )
    assert result['state'] == 'not-verified'
    assert result['marker_found'] is False


def test_hosts_file_shape_is_accepted_as_file_disclosure_evidence() -> None:
    result = VerificationEngine().verify_file_disclosure(
        '127.0.0.1 localhost\n::1 localhost',
        ('127.0.0.1',),
    )
    assert result['state'] == 'confirmed'
    assert result['confidence'] == 'high'


def test_reflection_records_encoding_and_context() -> None:
    result = VerificationEngine().verify_reflection(
        '<script>wscanary</script>', '<body><script>wscanary</script></body>'
    )
    assert result['payload_reflected'] is True
    assert result['unescaped_markup'] is True
    assert result['context'] == 'HTML/text context'


def test_differential_comparison_explains_response_change() -> None:
    result = VerificationEngine().compare_responses(
        'same page', 'same page with one result', 'empty page', 200, 200, 200
    )
    assert result['different_response'] is True
    assert result['positive_delta'] > 0
    assert 'positive_negative_similarity' in result


def test_baseline_only_change_is_not_boolean_injection_evidence() -> None:
    result = VerificationEngine().compare_responses(
        'normal application page', 'authentication redirect', 'authentication redirect',
        200, 302, 302,
    )
    assert result['different_response'] is False
    assert result['baseline_status_changed'] is True
    assert result['status_changed'] is False


def test_sql_comparison_accepts_small_result_table_difference() -> None:
    baseline = 'header' + ('x' * 400)
    positive = 'header' + ('x' * 400) + ('<tr>user</tr>' * 8)
    negative = 'header' + ('x' * 400) + 'No users found'
    result = VerificationEngine().compare_sql_responses(
        baseline, positive, negative, 200, 200, 200
    )
    assert result['different_response'] is True
    assert result['positive_negative_length_delta'] >= 40


def test_dvwa_mysql_error_signature_is_recognized() -> None:
    result = VerificationEngine().verify_sql_error(
        'Warning: mysqli_query(): You have an error in your SQL syntax; check the manual',
        [r'You have an error in your SQL syntax'],
    )
    assert result['error_signature_found'] is True
    assert result['state'] == 'verified'
