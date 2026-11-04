#!/bin/bash
# ==============================================================================
# AWS CodeBuild Local-to-Cloud ARM64 Wheel Builder
# Automates: Zipping local source -> S3 -> CodeBuild -> Compiling -> S3 -> Download
# ==============================================================================

# --- CONFIGURATION (Adjust these values) ---
PROJECT_NAME="your-codebuild-project-name"
S3_BUCKET="your-source-and-artifact-bucket"
LOCAL_DIST="./dist"

# --- INTERNAL VARS ---
TIMESTAMP=$(date +%s)
ZIP_NAME="source_${TIMESTAMP}.zip"
S3_SRC_KEY="codebuild-src/${ZIP_NAME}"
LOCAL_TEMP_DIR="./.codebuild_temp"

# Ensure we clean up on exit or failure
cleanup() {
    echo "🧹 Cleaning up temporary local files..."
    rm -rf "$LOCAL_TEMP_DIR"
    rm -f "$ZIP_NAME"
}
trap cleanup EXIT

echo "📁 Step 1: Packaging local source code..."
mkdir -p "$LOCAL_TEMP_DIR"
mkdir -p "$LOCAL_DIST"

# Zip your code, ignoring git, virtual environments, and old builds
zip -r "$ZIP_NAME" .     -x "*.git*"     -x "*venv*"     -x "*.env*"     -x "*__pycache__*"     -x "*dist*"     -x "*.egg-info*"     -x "*.codebuild_temp*" > /dev/null

if [ ! -f "$ZIP_NAME" ]; then
    echo "❌ Error: Failed to create source zip file."
    exit 1
fi

echo "📤 Step 2: Uploading source archive to S3 ($S3_SRC_KEY)..."
aws s3 cp "$ZIP_NAME" "s3://${S3_BUCKET}/${S3_SRC_KEY}" --quiet

echo "🚀 Step 3: Triggering ARM64 build on AWS CodeBuild..."
# Explicitly pass the source zip file location directly via CLI override
BUILD_JSON=$(aws codebuild start-build     --project-name "$PROJECT_NAME"     --source-type-override S3     --source-location-override "${S3_BUCKET}/${S3_SRC_KEY}"     --output json)

BUILD_ID=$(echo "$BUILD_JSON" | grep -o '"id": "[^"]*' | head -n1 | cut -d'"' -f4)

if [ -z "$BUILD_ID" ]; then
    echo "❌ Error: Failed to start CodeBuild project."
    exit 1
fi

echo "⏳ Step 4: Monitoring build status (ID: $BUILD_ID)..."
while true; do
    # Fetch status and target artifact location directly
    BUILD_INFO=$(aws codebuild batch-get-builds --ids "$BUILD_ID" --output json)
    STATUS=$(echo "$BUILD_INFO" | grep -o '"buildStatus": "[^"]*' | head -n1 | cut -d'"' -f4)
    
    if [ "$STATUS" = "SUCCEEDED" ]; then
        echo "✅ Cloud compilation completed successfully!"
        # Extract the S3 location where CodeBuild saved the finished artifact zip
        S3_OUT_LOCATION=$(echo "$BUILD_INFO" | grep -o '"location": "[^"]*' | head -n1 | cut -d'"' -f4)
        break
    elif [[ "$STATUS" =~ ^(FAILED|FAULT|STOPPED)$ ]]; then
        echo "❌ Build failed on AWS with status: $STATUS"
        echo "Check the AWS CloudWatch logs for debug details."
        exit 1
    fi
    
    sleep 10
done

# Standardize S3 path (strip ARN prefix if present)
S3_OUT_PATH=$(echo "$S3_OUT_LOCATION" | sed 's|^arn:aws:s3:::||')

echo "📥 Step 5: Downloading compiled .whl artifact from S3..."
aws s3 cp "s3://${S3_OUT_PATH}" "$LOCAL_TEMP_DIR/output.zip" --quiet

echo "📦 Step 6: Extracting wheel to $LOCAL_DIST..."
# CodeBuild packs artifacts into a zip. Extract only the .whl files out of it.
unzip -j -q "$LOCAL_TEMP_DIR/output.zip" "*.whl" -d "$LOCAL_DIST"

echo "🎉 Done! Your ARM64 Wheel file is ready in: $(ls -1 $LOCAL_DIST/*.whl | tail -n 1)"
