Write-Host "\033[0;32mDeploying updates to GitHub...\033[0m\n"

# Build the project.
hugo -t bare # if using a theme, replace with `hugo -t <YOURTHEME>`

# Go To Public folder
Set-Location public

# Add changes to git.
git add .

# Commit changes.
$msg = "rebuilding site $(Get-Date)" 

git commit -m "$msg"

# Push source and build repos.
git push origin master