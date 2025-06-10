const express = require('express');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const { PrismaClient } = require('@prisma/client');
const { authenticate, authorize } = require('../middleware/auth');
const { sendEmail } = require('../utils/email');
const { validateOptionalCUID } = require('../utils/validation');

const router = express.Router();
const prisma = new PrismaClient();

// Apply authentication middleware to all routes
router.use(authenticate);

// GET /api/invitations - List invitations
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    const user = req.user;

    let where = {};

    // Apply role-based filtering
    if (user.role === 'ORGANIZATION_MANAGER') {
      // Organization managers can see invitations they sent
      where.senderId = user.id;
    } else if (user.role === 'REVIEWER') {
      // Reviewers can see invitations sent to them
      where.OR = [
        { email: user.email },
        { receiverId: user.id }
      ];
    }
    // SUPER_ADMIN and SYSTEM_USER can see all invitations

    if (status) {
      where.status = status;
    }

    const [invitations, total] = await Promise.all([
      prisma.invitation.findMany({
        where,
        skip: parseInt(skip),
        take: parseInt(limit),
        include: {
          sender: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          },
          receiver: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          }
        },
        orderBy: { createdAt: 'desc' }
      }),
      prisma.invitation.count({ where })
    ]);

    res.json({
      success: true,
      data: {
        invitations,
        pagination: {
          total,
          page: parseInt(page),
          pages: Math.ceil(total / limit),
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('Get invitations error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch invitations'
    });
  }
});

// GET /api/invitations/:id - Get specific invitation
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const user = req.user;

    const invitation = await prisma.invitation.findUnique({
      where: { id },
      include: {
        sender: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        receiver: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    if (!invitation) {
      return res.status(404).json({
        success: false,
        message: 'Invitation not found'
      });
    }

    // Check access permissions
    let hasAccess = false;
    if (user.role === 'SUPER_ADMIN' || user.role === 'SYSTEM_USER') {
      hasAccess = true;
    } else if (user.role === 'ORGANIZATION_MANAGER') {
      hasAccess = invitation.senderId === user.id;
    } else if (user.role === 'REVIEWER') {
      hasAccess = invitation.email === user.email || invitation.receiverId === user.id;
    }

    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        message: 'Access denied to this invitation'
      });
    }

    res.json({
      success: true,
      data: invitation
    });
  } catch (error) {
    console.error('Get invitation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch invitation'
    });
  }
});

// POST /api/invitations - Send invitation
router.post('/',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER']),
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('role').isIn(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER', 'REVIEWER']).withMessage('Valid role is required'),
    validateOptionalCUID('projectId', 'Valid project ID required if provided')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation errors',
          errors: errors.array()
        });
      }

      const { email, role, projectId } = req.body;
      const user = req.user;

      // Check if user already exists
      const existingUser = await prisma.user.findUnique({
        where: { email }
      });

      // If inviting to a project, verify it exists and user has access
      if (projectId) {
        const project = await prisma.project.findUnique({
          where: { id: projectId },
          include: {
            organization: true
          }
        });

        if (!project) {
          return res.status(400).json({
            success: false,
            message: 'Project not found'
          });
        }

        // Check if user can invite to this project
        if (user.role === 'ORGANIZATION_MANAGER' && project.organization.managerId !== user.id) {
          return res.status(403).json({
            success: false,
            message: 'You can only invite reviewers to projects in organizations you manage'
          });
        }
      }

      // Check for existing pending invitation
      const existingInvitation = await prisma.invitation.findFirst({
        where: {
          email,
          status: 'PENDING',
          expiresAt: {
            gt: new Date()
          }
        }
      });

      if (existingInvitation) {
        return res.status(400).json({
          success: false,
          message: 'A pending invitation already exists for this email'
        });
      }

      // Generate invitation token
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      // Create invitation
      const invitation = await prisma.invitation.create({
        data: {
          email,
          role,
          token,
          expiresAt,
          senderId: user.id,
          projectId,
          receiverId: existingUser?.id
        },
        include: {
          sender: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          }
        }
      });

      // Send invitation email
      const invitationUrl = `${process.env.APP_URL}/accept-invitation?token=${token}`;
      const projectText = projectId ? 'to join a project' : '';
      
      await sendEmail({
        to: email,
        subject: `Invitation to join our platform ${projectText}`,
        html: `
          <h1>You're invited!</h1>
          <p>${user.firstName} ${user.lastName} has invited you to join our platform as a ${role.toLowerCase().replace('_', ' ')}.</p>
          ${projectId ? '<p>You have been invited to review a specific project.</p>' : ''}
          <p>Click the link below to accept the invitation:</p>
          <a href="${invitationUrl}">Accept Invitation</a>
          <p>This invitation will expire in 7 days.</p>
          <p>If you already have an account, you can simply log in to accept the invitation.</p>
        `
      });

      res.status(201).json({
        success: true,
        message: 'Invitation sent successfully',
        data: invitation
      });
    } catch (error) {
      console.error('Send invitation error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to send invitation'
      });
    }
  }
);

// PUT /api/invitations/:id - Update invitation status
router.put('/:id',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER']),
  [
    body('status').isIn(['PENDING', 'ACCEPTED', 'REJECTED', 'EXPIRED']).withMessage('Valid status is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation errors',
          errors: errors.array()
        });
      }

      const { id } = req.params;
      const { status } = req.body;

      const invitation = await prisma.invitation.update({
        where: { id },
        data: { status },
        include: {
          sender: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          },
          receiver: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          }
        }
      });

      res.json({
        success: true,
        message: 'Invitation updated successfully',
        data: invitation
      });
    } catch (error) {
      console.error('Update invitation error:', error);
      if (error.code === 'P2025') {
        return res.status(404).json({
          success: false,
          message: 'Invitation not found'
        });
      }
      res.status(500).json({
        success: false,
        message: 'Failed to update invitation'
      });
    }
  }
);

// DELETE /api/invitations/:id - Delete invitation
router.delete('/:id', authorize(['SUPER_ADMIN', 'SYSTEM_USER']), async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.invitation.delete({
      where: { id }
    });

    res.json({
      success: true,
      message: 'Invitation deleted successfully'
    });
  } catch (error) {
    console.error('Delete invitation error:', error);
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Invitation not found'
      });
    }
    res.status(500).json({
      success: false,
      message: 'Failed to delete invitation'
    });
  }
});

// POST /api/invitations/:id/resend - Resend invitation
router.post('/:id/resend',
  authorize(['SUPER_ADMIN', 'SYSTEM_USER', 'ORGANIZATION_MANAGER']),
  async (req, res) => {
    try {
      const { id } = req.params;
      const user = req.user;

      const invitation = await prisma.invitation.findUnique({
        where: { id },
        include: {
          sender: true
        }
      });

      if (!invitation) {
        return res.status(404).json({
          success: false,
          message: 'Invitation not found'
        });
      }

      // Check permissions
      if (user.role === 'ORGANIZATION_MANAGER' && invitation.senderId !== user.id) {
        return res.status(403).json({
          success: false,
          message: 'You can only resend invitations you sent'
        });
      }

      if (invitation.status !== 'PENDING') {
        return res.status(400).json({
          success: false,
          message: 'Can only resend pending invitations'
        });
      }

      // Generate new token and extend expiry
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      // Update invitation
      const updatedInvitation = await prisma.invitation.update({
        where: { id },
        data: {
          token,
          expiresAt
        }
      });

      // Resend email
      const invitationUrl = `${process.env.APP_URL}/accept-invitation?token=${token}`;
      const projectText = invitation.projectId ? 'to join a project' : '';
      
      await sendEmail({
        to: invitation.email,
        subject: `Reminder: Invitation to join our platform ${projectText}`,
        html: `
          <h1>Reminder: You're invited!</h1>
          <p>${invitation.sender.firstName} ${invitation.sender.lastName} has invited you to join our platform as a ${invitation.role.toLowerCase().replace('_', ' ')}.</p>
          ${invitation.projectId ? '<p>You have been invited to review a specific project.</p>' : ''}
          <p>Click the link below to accept the invitation:</p>
          <a href="${invitationUrl}">Accept Invitation</a>
          <p>This invitation will expire in 7 days.</p>
          <p>If you already have an account, you can simply log in to accept the invitation.</p>
        `
      });

      res.json({
        success: true,
        message: 'Invitation resent successfully',
        data: updatedInvitation
      });
    } catch (error) {
      console.error('Resend invitation error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to resend invitation'
      });
    }
  }
);

module.exports = router; 