dotnet pack -c Release -o ./nupkg/
dotnet tool install --global  KeyVaultCa.Cli --add-source ./nupkg/
