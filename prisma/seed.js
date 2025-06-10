// Load configuration first
require('../config');

const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  console.log('Starting database seeding...');

  // Create super admin user
  const hashedPassword = await bcrypt.hash('admin123', 12);
  
  const superAdmin = await prisma.user.upsert({
    where: { email: 'admin@example.com' },
    update: {},
    create: {
      email: 'admin@example.com',
      password: hashedPassword,
      firstName: 'Super',
      lastName: 'Admin',
      role: 'SUPER_ADMIN',
      emailVerified: true,
      isActive: true
    }
  });

  console.log('Created super admin:', superAdmin.email);

  // Create system user
  const systemUser = await prisma.user.upsert({
    where: { email: 'system@example.com' },
    update: {},
    create: {
      email: 'system@example.com',
      password: hashedPassword,
      firstName: 'System',
      lastName: 'User',
      role: 'SYSTEM_USER',
      emailVerified: true,
      isActive: true
    }
  });

  console.log('Created system user:', systemUser.email);

  // Create organization manager
  const orgManager = await prisma.user.upsert({
    where: { email: 'manager@example.com' },
    update: {},
    create: {
      email: 'manager@example.com',
      password: hashedPassword,
      firstName: 'Organization',
      lastName: 'Manager',
      role: 'ORGANIZATION_MANAGER',
      emailVerified: true,
      isActive: true
    }
  });

  console.log('Created organization manager:', orgManager.email);

  // Create reviewer
  const reviewer = await prisma.user.upsert({
    where: { email: 'reviewer@example.com' },
    update: {},
    create: {
      email: 'reviewer@example.com',
      password: hashedPassword,
      firstName: 'Test',
      lastName: 'Reviewer',
      role: 'REVIEWER',
      emailVerified: true,
      isActive: true
    }
  });

  console.log('Created reviewer:', reviewer.email);

  // Create sample organization
  const organization = await prisma.organization.upsert({
    where: { id: 'sample-org-id' },
    update: {},
    create: {
      id: 'sample-org-id',
      name: 'Sample Organization',
      description: 'A sample organization for testing',
      managerId: orgManager.id
    }
  });

  console.log('Created organization:', organization.name);

  // Add members to organization
  await prisma.organizationMember.upsert({
    where: {
      userId_organizationId: {
        userId: reviewer.id,
        organizationId: organization.id
      }
    },
    update: {},
    create: {
      userId: reviewer.id,
      organizationId: organization.id
    }
  });

  console.log('Added reviewer to organization');

  // Create sample project
  const project = await prisma.project.upsert({
    where: { id: 'sample-project-id' },
    update: {},
    create: {
      id: 'sample-project-id',
      name: 'Sample Project',
      description: 'A sample project for testing',
      organizationId: organization.id
    }
  });

  console.log('Created project:', project.name);

  // Add reviewer to project
  await prisma.projectReviewer.upsert({
    where: {
      userId_projectId: {
        userId: reviewer.id,
        projectId: project.id
      }
    },
    update: {},
    create: {
      userId: reviewer.id,
      projectId: project.id
    }
  });

  console.log('Added reviewer to project');

  // Create sample tour
  const tour = await prisma.tour.upsert({
    where: { id: 'sample-tour-id' },
    update: {},
    create: {
      id: 'sample-tour-id',
      name: 'Sample Tour',
      version: '1.0.0',
      description: 'A sample tour for testing',
      data: {
        steps: [
          {
            title: 'Welcome',
            content: 'Welcome to our application tour',
            target: '#welcome'
          },
          {
            title: 'Navigation',
            content: 'Use the navigation menu to explore',
            target: '#nav'
          }
        ]
      },
      projectId: project.id
    }
  });

  console.log('Created tour:', tour.name);

  // Set as current tour
  await prisma.project.update({
    where: { id: project.id },
    data: { currentTourId: tour.id }
  });

  console.log('Set current tour for project');

  // Create sample comment
  await prisma.comment.create({
    data: {
      content: 'This is a sample comment on the tour.',
      userId: reviewer.id,
      tourId: tour.id
    }
  });

  console.log('Created sample comment');

  console.log('Database seeding completed!');
  console.log('\nLogin credentials:');
  console.log('Super Admin: admin@example.com / admin123');
  console.log('System User: system@example.com / admin123');
  console.log('Org Manager: manager@example.com / admin123');
  console.log('Reviewer: reviewer@example.com / admin123');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  }); 