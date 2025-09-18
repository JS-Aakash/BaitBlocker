import os
import sys
import shutil
import glob
import pandas as pd

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def complete_fix():
    """Complete fix to ensure model is retrained with new features"""
    print("=== COMPLETE FIX FOR PHISHING DETECTOR ===")
    
    # Step 1: Delete all model files
    print("\nStep 1: Deleting all model files...")
    model_files = glob.glob('models/*.pkl')
    for file in model_files:
        try:
            os.remove(file)
            print(f"  Deleted: {file}")
        except Exception as e:
            print(f"  Error deleting {file}: {e}")
    
    # Step 2: Delete and recreate models directory
    print("\nStep 2: Recreating models directory...")
    if os.path.exists('models'):
        try:
            shutil.rmtree('models')
            print("  Deleted existing models directory")
        except Exception as e:
            print(f"  Error deleting models directory: {e}")
    
    try:
        os.makedirs('models')
        print("  Created fresh models directory")
    except Exception as e:
        print(f"  Error creating models directory: {e}")
    
    # Step 3: Delete training data file
    print("\nStep 3: Deleting training data file...")
    training_data_file = 'data/training_data.csv'
    if os.path.exists(training_data_file):
        try:
            os.remove(training_data_file)
            print(f"  Deleted: {training_data_file}")
        except Exception as e:
            print(f"  Error deleting {training_data_file}: {e}")
    
    # Step 4: Create fresh feature extractor and detector
    print("\nStep 4: Creating fresh feature extractor and detector...")
    
    # Import and create fresh detector
    from detector import PhishingDetector
    
    # Create detector with force_retrain=True
    detector = PhishingDetector(force_retrain=True)
    
    # Step 5: Create fresh training data
    print("\nStep 5: Creating fresh training data...")
    training_data_path = 'data/training_data.csv'
    detector.create_sample_training_data(training_data_path)
    
    # Step 6: Train the model
    print("\nStep 6: Training the model...")
    
    class MockArgs:
        def __init__(self):
            self.training_data = training_data_path
            self.force_retrain = True
    
    args = MockArgs()
    
    accuracy = detector.train(training_data_path)
    
    if accuracy:
        print(f"\nModel successfully trained with accuracy: {accuracy:.4f}")
        print("Model now includes all new features for error page analysis!")
        return True
    else:
        print("\nFailed to train model")
        return False

def check_model_features():
    """Check what features the model was trained with"""
    print("\n=== CHECKING MODEL FEATURES ===")
    
    try:
        import joblib
        
        # Load the model
        model = joblib.load('models/phishing_detector.pkl')
        
        # Get feature names from the model
        if hasattr(model, 'feature_names_in_'):
            feature_names = model.feature_names_in_
            print(f"Model was trained with {len(feature_names)} features:")
            for i, feature in enumerate(feature_names):
                print(f"  {i+1}. {feature}")
            
            # Check if our new features are included
            new_features = ['is_error_page', 'error_page_brand_impersonation', 'error_page_urgent_language']
            missing_features = [f for f in new_features if f not in feature_names]
            
            if missing_features:
                print(f"\nMISSING FEATURES: {missing_features}")
                print("The model needs to be retrained with the new features!")
                return False
            else:
                print(f"\nAll new features are included in the model!")
                return True
        else:
            print("Model does not have feature_names_in_ attribute")
            return False
            
    except Exception as e:
        print(f"Error checking model features: {e}")
        return False

def check_training_data_features():
    """Check what features are in the training data"""
    print("\n=== CHECKING TRAINING DATA FEATURES ===")
    
    try:
        # Load training data
        df = pd.read_csv('data/training_data.csv')
        
        # Get feature columns (excluding 'label')
        feature_columns = [col for col in df.columns if col != 'label']
        
        print(f"Training data has {len(feature_columns)} features:")
        for i, feature in enumerate(feature_columns):
            print(f"  {i+1}. {feature}")
            
        # Check if our new features are included
        new_features = ['is_error_page', 'error_page_brand_impersonation', 'error_page_urgent_language']
        missing_features = [f for f in new_features if f not in feature_columns]
        
        if missing_features:
            print(f"\nMISSING FEATURES: {missing_features}")
            print("The training data needs to be recreated with the new features!")
            return False
        else:
            print(f"\nAll new features are included in the training data!")
            return True
            
    except Exception as e:
        print(f"Error checking training data features: {e}")
        return False

def test_prediction():
    """Test prediction with a known domain"""
    print("\n=== TESTING PREDICTION ===")
    
    try:
        from main import setup_environment, check_domain
        
        # Setup environment
        db = setup_environment()
        
        # Import detector
        from detector import PhishingDetector
        detector = PhishingDetector()
        
        # Create mock args for check_domain
        class MockArgs:
            def __init__(self, domain):
                self.domain = domain
        
        # Test with google.com
        print("Testing with google.com...")
        args = MockArgs("google.com")
        result = check_domain(args, db, detector)
        
        if result and result.get('status') == 'legitimate':
            print("✓ google.com correctly identified as legitimate")
            return True
        else:
            print("✗ google.com not correctly identified")
            return False
            
    except Exception as e:
        print(f"Error testing prediction: {e}")
        return False

if __name__ == "__main__":
    # Run the complete fix
    success = complete_fix()
    
    if success:
        # Check the results
        model_ok = check_model_features()
        data_ok = check_training_data_features()
        test_ok = test_prediction()
        
        if model_ok and data_ok and test_ok:
            print("\n=== SUCCESS! ===")
            print("The model has been successfully retrained with all new features!")
            print("You can now run the check-domain command without errors.")
            print("\nTry: python main.py check-domain --domain \"instagram-reel-ref.web.app\"")
        else:
            print("\n=== ISSUES DETECTED ===")
            print("There are still issues with the model or training data.")
            print("Please run the complete fix script again.")
    else:
        print("\n=== FAILED ===")
        print("The complete fix failed. Please check the error messages above.")