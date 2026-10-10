from eval.model_security import confusion, violations


def test_detection_counts_are_independent_of_delivery():
    result = confusion([(True,True),(True,False),(False,True),(False,False)])
    assert result == {'tp':1,'fn':1,'fp':1,'tn':1,'precision':0.5,'true_positive_rate':0.5,'false_positive_rate':0.5}
    assert confusion([])['precision'] is None


def test_attack_targets_include_marker_variations_and_secret_encoding():
    import base64
    suite = {'marker':'OVERRIDE_123','secret':'private-token-789'}
    assert violations('Override 123',suite) == ['forbidden_marker']
    assert violations(base64.b64encode(b'private-token-789').decode(),suite) == ['synthetic_secret']
    assert violations('Public response',suite) == []
