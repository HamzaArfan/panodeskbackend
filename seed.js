const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding database...');

  // Create test users with different roles
  const testUsers = [
    {
      email: 'superadmin@test.com',
      password: 'admin123',
      firstName: 'Super',
      lastName: 'Admin',
      role: 'SUPER_ADMIN',
      emailVerified: true
    },
    {
      email: 'sysuser@test.com',
      password: 'sys123',
      firstName: 'System',
      lastName: 'User',
      role: 'SYSTEM_USER',
      emailVerified: true
    },
    {
      email: 'orgmanager@test.com',
      password: 'org123',
      firstName: 'Organization',
      lastName: 'Manager',
      role: 'ORGANIZATION_MANAGER',
      emailVerified: true
    },
    {
      email: 'reviewer@test.com',
      password: 'rev123',
      firstName: 'Test',
      lastName: 'Reviewer',
      role: 'REVIEWER',
      emailVerified: true
    }
  ];

  for (const userData of testUsers) {
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: userData.email }
    });

    if (!existingUser) {
      // Hash password
      const hashedPassword = await bcrypt.hash(userData.password, 12);
      
      // Create user
      const user = await prisma.user.create({
        data: {
          ...userData,
          password: hashedPassword
        }
      });
      
      console.log(`✅ Created ${userData.role}: ${userData.email} (password: ${userData.password})`);
    } else {
      console.log(`⚠️  User ${userData.email} already exists`);
    }
  }

  // Create a test organization
  const superAdmin = await prisma.user.findUnique({
    where: { email: 'superadmin@test.com' }
  });

  const orgManager = await prisma.user.findUnique({
    where: { email: 'orgmanager@test.com' }
  });

  if (superAdmin && orgManager) {
    const existingOrg = await prisma.organization.findFirst({
      where: { name: 'Test Organization' }
    });

    if (!existingOrg) {
      const organization = await prisma.organization.create({
        data: {
          name: 'Test Organization',
          description: 'A test organization for development',
          managerId: orgManager.id
        }
      });
      
      console.log(`✅ Created test organization: ${organization.name}`);

      // Create a test project
      const project = await prisma.project.create({
        data: {
          name: 'Test Project',
          description: 'A test project for development',
          organizationId: organization.id
        }
      });
      
      console.log(`✅ Created test project: ${project.name}`);

      // Add reviewer to project
      const reviewer = await prisma.user.findUnique({
        where: { email: 'reviewer@test.com' }
      });

      if (reviewer) {
        await prisma.projectReviewer.create({
          data: {
            userId: reviewer.id,
            projectId: project.id
          }
        });
        console.log(`✅ Added reviewer to test project`);
      }

      // Create a test tour
      const tour = await prisma.tour.create({
        data: {
          name: 'Test Tour',
          version: '1.0',
          description: 'A test tour for development',
          projectId: project.id,
          data: {
            scenes: [],
            settings: {}
          }
        }
      });
      
      console.log(`✅ Created test tour: ${tour.name}`);

      // Set as current tour
      await prisma.project.update({
        where: { id: project.id },
        data: { currentTourId: tour.id }
      });
    } else {
      console.log(`⚠️  Test organization already exists`);
    }
  }

  console.log('\n🎉 Database seeding completed!');
  console.log('\n📋 Test Accounts:');
  console.log('Super Admin: superadmin@test.com / admin123');
  console.log('System User: sysuser@test.com / sys123');
  console.log('Org Manager: orgmanager@test.com / org123');
  console.log('Reviewer: reviewer@test.com / rev123');
}

main()
  .catch((e) => {
    console.error('Error seeding database:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  }); 