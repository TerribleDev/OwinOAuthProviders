namespace :nuget do

  # If we don't have a copy of nuget, download it
  task :bootstrap do
    puts 'Ensuring NuGet exists in tools/NuGet'

    if !FileTest.exist?("#{NUGET}/nuget.exe")
      puts 'Downloading nuget from nuget.org'

      begin
      FileUtils.mkdir_p("#{NUGET}")
      File.open("#{NUGET}/nuget.exe", "wb") do |file|
        file.write open('http://nuget.org/nuget.exe', {ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE}).read
      end
    rescue
      FileUtils.rm_rf("#{NUGET}/nuget.exe")
      File.open("#{NUGET}/nuget.exe", "wb") do |file|
        file.write open('https://dist.nuget.org/win-x86-commandline/v3.2.0/nuget.exe', {ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE}).read
      end
    end
    end
  end
  desc 'Fetch nuget dependencies for all packages'
  task :fetch => :bootstrap do

    # If we aren't running under windows, assume we're using mono
    CMD_PREFIX = ""
    if !OS.windows?
      CMD_PREFIX = "mono"
      begin
        sh "mozroots --import --sync" #attempt to sync ssl things...
        rescue
        end
    end

    # Make sure we get solution-level deps
    #sh "#{CMD_PREFIX} #{NUGET}/nuget.exe i .nuget/packages.config -o packages"

   
      sh "nuget.exe restore"
   
  end

end
