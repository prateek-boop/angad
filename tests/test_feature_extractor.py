from ml_engine.feature_extractor import FeatureExtractor, demo


def test_feature_extractor_self_check():
    demo()


def test_feature_count_and_range():
    fx = FeatureExtractor()
    features = fx.extract("https://example.com/path?x=1")
    assert len(features) == 41
    assert all(isinstance(f, float) for f in features)
