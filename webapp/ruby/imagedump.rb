require 'mysql2'
require 'redis'

def db
  return @db_client if defined?(@db_client)

  @db_client = Mysql2::Client.new(
    host: ENV.fetch('ISUBATA_DB_HOST') { '127.0.0.1' },
    port: ENV.fetch('ISUBATA_DB_PORT') { '3306' },
    username: ENV.fetch('ISUBATA_DB_USER') { 'root' },
    password: ENV.fetch('ISUBATA_DB_PASSWORD') { '' },
    database: 'isubata',
    encoding: 'utf8mb4'
  )
  @db_client.query('SET SESSION sql_mode=\'TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY\'')
  @db_client
end



statement = db.prepare('SELECT * FROM image')
rows = statement.execute(file_name)
statement.close
rows.each do |row|
  # /home/isucon/isubata/webapp/public
  File.open("/home/isucon/isubata/webapp/public/icons/#{row['name']}", "w") do |file|
    file.print(row['data'])
  end
end

